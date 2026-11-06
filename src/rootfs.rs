use anyhow::{Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use std::fs;
use std::path::Path;
use tracing::{debug, info};

pub fn setup_rootfs(new_root: &Path) -> Result<()> {
    info!("Setting up rootfs at {:?}", new_root);

    if !new_root.exists() {
        anyhow::bail!("Rootfs path does not exist: {:?}", new_root);
    }

    // 1. Make parent mounts private so our mounts don't propagate to host
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("Failed to mark / as MS_REC | MS_PRIVATE")?;

    // 2. Ensure new_root is a mountpoint by bind mounting it onto itself
    mount(
        Some(new_root),
        new_root,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .with_context(|| format!("Failed to bind mount rootfs on {:?}", new_root))?;

    // 3. Prepare old_root directory for pivot_root swap
    let old_root = new_root.join(".old_root");
    if !old_root.exists() {
        fs::create_dir_all(&old_root)
            .with_context(|| format!("Failed to create old_root placeholder at {:?}", old_root))?;
    }

    // 4. Perform pivot_root
    debug!("Executing pivot_root(new={:?}, old={:?})", new_root, old_root);
    nix::unistd::pivot_root(new_root, &old_root)
        .context("pivot_root failed. Ensure minirun is run with root/CAP_SYS_ADMIN privileges.")?;

    // 5. Change current working directory to new /
    std::env::set_current_dir("/").context("Failed to chdir to / after pivot_root")?;

    // 6. Mount essential virtual filesystems
    setup_virtual_filesystems()?;

    // 7. Unmount old host root and clean up
    umount2("/.old_root", MntFlags::MNT_DETACH)
        .context("Failed to unmount /.old_root via MNT_DETACH")?;
    let _ = fs::remove_dir("/.old_root");

    info!("Rootfs pivot completed successfully");
    Ok(())
}

/// Mounts /proc, /sys, /dev for full container isolation
fn setup_virtual_filesystems() -> Result<()> {
    // /proc (Crucial for PID isolation: ps, top, /proc/self)
    let proc_path = Path::new("/proc");
    if !proc_path.exists() {
        let _ = fs::create_dir_all(proc_path);
    }
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )
    .context("Failed to mount container /proc")?;
    debug!("Mounted isolated /proc");

    // /sys (Mounted read-only for security)
    let sys_path = Path::new("/sys");
    if sys_path.exists() {
        let _ = mount(
            Some("sysfs"),
            "/sys",
            Some("sysfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV | MsFlags::MS_RDONLY,
            None::<&str>,
        );
        debug!("Mounted container /sys (read-only)");
    }

    Ok(())
}
