use anyhow::{Context, Result};
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, pipe, read, sethostname, write, ForkResult, Pid};
use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::path::Path;
use tracing::{debug, error, info, warn};

use crate::cgroups::CgroupV2Manager;
use crate::cli::RunArgs;
use crate::rootfs::setup_rootfs;

pub struct ContainerRuntime {
    args: RunArgs,
    container_id: String,
}

impl ContainerRuntime {
    pub fn new(args: RunArgs) -> Self {
        let container_id = format!("minirun-{}", std::process::id());
        Self {
            args,
            container_id,
        }
    }

    pub fn run(&self) -> Result<i32> {
        info!("Initializing container {}", self.container_id);

        // Setup Cgroups v2 manager if resource limits are requested
        let cgroup_mgr = if self.args.memory.is_some()
            || self.args.cpus.is_some()
            || self.args.pids.is_some()
        {
            match CgroupV2Manager::new(&self.container_id) {
                Ok(mgr) => Some(mgr),
                Err(e) => {
                    warn!("Cgroup initialization warning: {}. Continuing without cgroup limits.", e);
                    None
                }
            }
        } else {
            None
        };

        // Two-way synchronization pipes:
        // pipe_c2p: child -> parent (child signals it created userns)
        // pipe_p2c: parent -> child (parent signals cgroups & userns maps are ready)
        let (c2p_read_fd, c2p_write_fd) = pipe().context("Failed to create child-to-parent pipe")?;
        let (p2c_read_fd, p2c_write_fd) = pipe().context("Failed to create parent-to-child pipe")?;

        match unsafe { fork() }.context("Fork failed")? {
            ForkResult::Child => {
                drop(c2p_read_fd);
                drop(p2c_write_fd);

                // If rootless, unshare CLONE_NEWUSER first, then signal parent to configure uid/gid maps
                if self.args.rootless {
                    debug!("Child unsharing CLONE_NEWUSER");
                    if let Err(e) = unshare(CloneFlags::CLONE_NEWUSER) {
                        error!("Failed to unshare CLONE_NEWUSER: {}", e);
                        std::process::exit(1);
                    }
                    // Notify parent that userns is created
                    write(&c2p_write_fd, &[1u8]).ok();
                }
                drop(c2p_write_fd);

                // Wait for parent signal that maps and cgroups are ready
                let mut buf = [0u8; 1];
                let _ = read(p2c_read_fd.as_raw_fd(), &mut buf);
                drop(p2c_read_fd);

                // Run child container entrypoint
                if let Err(e) = self.child_entrypoint() {
                    error!("Container init error: {:?}", e);
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
            ForkResult::Parent { child } => {
                drop(c2p_write_fd);
                drop(p2c_read_fd);
                info!("Container process spawned with host PID {}", child);

                // If rootless, wait for child to unshare userns, then write uid_map/gid_map from parent
                if self.args.rootless {
                    let mut buf = [0u8; 1];
                    let _ = read(c2p_read_fd.as_raw_fd(), &mut buf);
                    drop(c2p_read_fd);

                    if let Err(e) = setup_user_namespace_mappings(child) {
                        warn!("User namespace UID/GID mapping error: {}", e);
                    } else {
                        info!("Configured rootless user namespace (mapped container root -> host user)");
                    }
                } else {
                    drop(c2p_read_fd);
                }

                // Configure cgroups before releasing child
                if let Some(ref mgr) = cgroup_mgr {
                    if let Err(e) = mgr.add_process(child.as_raw()) {
                        warn!("Failed to attach PID to cgroup: {}", e);
                    }
                    if let Some(ref mem) = self.args.memory {
                        let _ = mgr.apply_memory_limit(mem);
                    }
                    if let Some(cpus) = self.args.cpus {
                        let _ = mgr.apply_cpu_limit(cpus);
                    }
                    if let Some(pids) = self.args.pids {
                        let _ = mgr.apply_pids_limit(pids);
                    }
                }

                // Signal child to proceed
                write(&p2c_write_fd, &[1u8]).ok();
                drop(p2c_write_fd);

                // Wait for container process to exit
                self.wait_for_child(child)
            }
        }
    }

    fn child_entrypoint(&self) -> Result<()> {
        // Unshare isolation namespaces (PID, Mount, UTS, IPC, Network)
        let flags = CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWIPC
            | CloneFlags::CLONE_NEWNET;

        debug!("Child unsharing container namespaces: {:?}", flags);
        unshare(flags).context("Failed to unshare container namespaces")?;

        // 1. Fork so the grandchild process becomes PID 1 in the new PID namespace
        match unsafe { fork() }.context("Sub-fork for PID 1 failed")? {
            ForkResult::Parent { child: pid1 } => {
                debug!("PID namespace init waiting for container PID 1 ({})", pid1);
                match waitpid(pid1, None)? {
                    WaitStatus::Exited(_, code) => std::process::exit(code),
                    WaitStatus::Signaled(_, sig, _) => std::process::exit(128 + sig as i32),
                    _ => std::process::exit(0),
                }
            }
            ForkResult::Child => {
                // This process is PID 1 in the new PID namespace!
                debug!("Running as container PID 1 (internal PID: {})", nix::unistd::getpid());

                // 2. Set hostname inside container
                debug!("Setting container hostname to '{}'", self.args.hostname);
                if let Err(e) = sethostname(&self.args.hostname) {
                    warn!("Could not set hostname: {}", e);
                }

                // 3. Setup root filesystem or isolated /proc
                if let Some(ref rootfs_path) = self.args.rootfs {
                    setup_rootfs(rootfs_path)?;
                } else {
                    // Remount /proc in new PID namespace if no custom rootfs is provided
                    debug!("No custom rootfs provided, isolating /proc in current mount namespace");
                    let _ = nix::mount::mount(
                        None::<&str>,
                        "/",
                        None::<&str>,
                        nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
                        None::<&str>,
                    );
                    let _ = nix::mount::mount(
                        Some("proc"),
                        "/proc",
                        Some("proc"),
                        nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV | nix::mount::MsFlags::MS_NOEXEC,
                        None::<&str>,
                    );
                }

                // 4. Prepare command and arguments for execvp
                let c_command = CString::new(self.args.command.clone())
                    .context("Command contains null byte")?;
                let mut c_args = vec![c_command.clone()];
                for arg in &self.args.args {
                    c_args.push(CString::new(arg.clone()).context("Argument contains null byte")?);
                }

                info!("Executing as PID 1: {} {:?}", self.args.command, self.args.args);
                nix::unistd::execvp(&c_command, &c_args)
                    .with_context(|| format!("Failed to exec command: '{}'", self.args.command))?;

                Ok(())
            }
        }
    }

    fn wait_for_child(&self, child: Pid) -> Result<i32> {
        debug!("Parent waiting for child PID {}...", child);
        match waitpid(child, None).context("waitpid failed")? {
            WaitStatus::Exited(_, status) => {
                info!("Container process exited with status {}", status);
                Ok(status)
            }
            WaitStatus::Signaled(_, sig, _) => {
                info!("Container process killed by signal {:?}", sig);
                Ok(128 + sig as i32)
            }
            _ => Ok(0),
        }
    }
}

/// Sets up user namespace UID/GID mappings so container process runs as root (UID 0) inside container
fn setup_user_namespace_mappings(pid: Pid) -> Result<()> {
    let uid = nix::unistd::getuid().as_raw();
    let gid = nix::unistd::getgid().as_raw();

    // 1. Write 'deny' to /proc/<pid>/setgroups before writing gid_map (required for unprivileged users)
    let setgroups_path = format!("/proc/{}/setgroups", pid);
    if Path::new(&setgroups_path).exists() {
        std::fs::write(&setgroups_path, "deny")
            .with_context(|| format!("Failed to write 'deny' to {}", setgroups_path))?;
    }

    // 2. Map container GID 0 to host GID
    let gid_map_path = format!("/proc/{}/gid_map", pid);
    std::fs::write(&gid_map_path, format!("0 {} 1\n", gid))
        .with_context(|| format!("Failed to write gid_map at {}", gid_map_path))?;

    // 3. Map container UID 0 to host UID
    let uid_map_path = format!("/proc/{}/uid_map", pid);
    std::fs::write(&uid_map_path, format!("0 {} 1\n", uid))
        .with_context(|| format!("Failed to write uid_map at {}", uid_map_path))?;

    debug!("Mapped container UID/GID 0 to host UID/GID {}/{}", uid, gid);
    Ok(())
}
