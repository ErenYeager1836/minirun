use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::MapCore;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

// Include generated skeleton from build.rs
#[allow(clippy::all)]
#[allow(dead_code)]
mod minirun_guard_skel {
    include!(concat!(env!("OUT_DIR"), "/minirun_guard.skel.rs"));
}
use minirun_guard_skel::*;

/*
 * ==============================================================================
 * Rust Representations of Shared Guard BPF Types
 * ==============================================================================
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuardMode {
    None,
    Audit,
    Enforce,
}

impl std::fmt::Display for GuardMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardMode::None => write!(f, "none"),
            GuardMode::Audit => write!(f, "audit"),
            GuardMode::Enforce => write!(f, "enforce"),
        }
    }
}

pub const GUARD_EVENT_EXEC_ATTEMPT: u32 = 1;
pub const GUARD_EVENT_EXEC_RESOLVED: u32 = 2;
pub const GUARD_EVENT_CONNECT: u32 = 3;
pub const GUARD_EVENT_OPENAT: u32 = 4;
pub const GUARD_EVENT_DUP: u32 = 5;

pub const GUARD_SEV_INFO: u32 = 0;
pub const GUARD_SEV_LOW: u32 = 1;
pub const GUARD_SEV_MEDIUM: u32 = 2;
pub const GUARD_SEV_HIGH: u32 = 3;
pub const GUARD_SEV_CRITICAL: u32 = 4;

pub const GUARD_FLAG_IN_KERNEL_KILL: u32 = 1 << 0;
pub const GUARD_FLAG_INIT_EXEC: u32 = 1 << 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GuardPathPayload {
    pub path: [u8; 256],
    pub flags: i32,
    pub dfd: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GuardSockPayload {
    pub family: u16,
    pub dport: u16,
    pub daddr_v4: u32,
    pub daddr_v6: [u8; 16],
    pub sun_path: [u8; 108],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GuardDupPayload {
    pub oldfd: i32,
    pub newfd: i32,
    pub flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union GuardPayload {
    pub path: GuardPathPayload,
    pub sock: GuardSockPayload,
    pub dup: GuardDupPayload,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GuardEvent {
    pub event_type: u32,
    pub severity: u32,
    pub ts_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
    pub flags: u32,
    pub container_idx: u32,
    pub payload: GuardPayload,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CgroupConfig {
    pub container_idx: u32,
    pub mode: u32,
    pub flags: u32,
}

/*
 * ==============================================================================
 * Structured Alert Representation
 * ==============================================================================
 */

#[derive(Debug, serde::Serialize)]
pub struct GuardAlert {
    pub timestamp: String,
    pub container_id: String,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub comm: String,
    pub severity: String,
    pub event_type: String,
    pub details: String,
    pub enforced: bool,
}

/*
 * ==============================================================================
 * Correlation State Table (Tgid + Lineage PPID with TTL)
 * ==============================================================================
 */

#[derive(Debug)]
struct ProcessState {
    last_seen: Instant,
    has_connected: bool,
    connected_target: Option<String>,
    dup_fds: HashSet<i32>,
    reverse_shell_alerted: bool,
}

impl ProcessState {
    fn new() -> Self {
        Self {
            last_seen: Instant::now(),
            has_connected: false,
            connected_target: None,
            dup_fds: HashSet::new(),
            reverse_shell_alerted: false,
        }
    }
}

pub const MAX_CORRELATION_STATES: usize = 4096;
pub const BATCH_EVICTION_SIZE: usize = 256;

pub struct CorrelationEngine {
    states: HashMap<u32, ProcessState>,
    ttl: Duration,
    last_sweep: Instant,
}

impl CorrelationEngine {
    pub fn new(ttl: Duration) -> Self {
        Self {
            states: HashMap::new(),
            ttl,
            last_sweep: Instant::now(),
        }
    }

    /// Periodic stale eviction: sweeps at most once per second to prevent O(n) scan overhead per event
    pub fn maybe_evict_stale(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_sweep) >= Duration::from_secs(1) {
            self.last_sweep = now;
            self.states.retain(|_, s| now.duration_since(s.last_seen) < self.ttl);
        }
    }

    pub fn evict_stale(&mut self) {
        let now = Instant::now();
        self.last_sweep = now;
        self.states.retain(|_, s| now.duration_since(s.last_seen) < self.ttl);
    }

    fn get_or_create(&mut self, tgid: u32, ppid: u32) -> &mut ProcessState {
        self.maybe_evict_stale();

        if !self.states.contains_key(&tgid) {
            // Under a fork storm, enforce bounded capacity via batch eviction of oldest entries
            if self.states.len() >= MAX_CORRELATION_STATES {
                let mut entries: Vec<(u32, Instant)> = self.states.iter().map(|(&t, s)| (t, s.last_seen)).collect();
                entries.sort_unstable_by_key(|&(_, last_seen)| last_seen);
                let to_remove = BATCH_EVICTION_SIZE.min(entries.len());
                for (old_tgid, _) in &entries[..to_remove] {
                    self.states.remove(old_tgid);
                }
            }

            // Check if parent state exists to inherit socket/fd state across forks
            let mut state = ProcessState::new();
            if let Some(parent) = self.states.get(&ppid) {
                state.has_connected = parent.has_connected;
                state.connected_target = parent.connected_target.clone();
                state.dup_fds = parent.dup_fds.clone();
            }
            self.states.insert(tgid, state);
        }
        let state = self.states.get_mut(&tgid).unwrap();
        state.last_seen = Instant::now();
        state
    }
}

/*
 * ==============================================================================
 * Guard Runtime Engine
 * ==============================================================================
 */

pub struct Guard {
    pub mode: GuardMode,
    pub json_output: bool,
    skel: &'static MinirunGuardSkel<'static>,
    shutdown_flag: Arc<AtomicBool>,
    event_worker: Option<JoinHandle<()>>,
    container_cgroups: Arc<Mutex<HashMap<u64, (String, PathBuf)>>>, // cgid -> (container_id, cgroup_path)
    pub killed_by_guard: Arc<AtomicBool>,
}

impl Guard {
    /// Pre-flight environment check before loading eBPF
    pub fn check_prerequisites() -> Result<()> {
        // 1. Root privileges
        if nix::unistd::geteuid().as_raw() != 0 {
            anyhow::bail!("minirun Guard requires root privileges (CAP_BPF, CAP_PERFMON, CAP_SYS_RESOURCE).");
        }

        // 2. Kernel version >= 5.14
        let uts = nix::sys::utsname::uname().context("Failed to query uname")?;
        let release = uts.release().to_string_lossy();
        if let Some((major, minor)) = parse_kernel_version(&release) {
            if major < 5 || (major == 5 && minor < 14) {
                anyhow::bail!("minirun Guard requires Linux kernel 5.14+ (detected: {})", release);
            }
        }

        // 3. Kernel BTF support (/sys/kernel/btf/vmlinux)
        if !Path::new("/sys/kernel/btf/vmlinux").exists() {
            anyhow::bail!("minirun Guard requires kernel BTF support (/sys/kernel/btf/vmlinux not found).");
        }

        // 4. Cgroups v2 unified hierarchy
        if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            anyhow::bail!("minirun Guard requires cgroups v2 unified hierarchy (/sys/fs/cgroup/cgroup.controllers not found).");
        }

        Ok(())
    }

    /// Raise RLIMIT_MEMLOCK to allow BPF map allocations
    pub fn bump_memlock_rlimit() -> Result<()> {
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        // SAFETY: Calling libc setrlimit with valid pointer to struct rlimit
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            warn!("Failed to set RLIMIT_MEMLOCK to infinity: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Initialize and attach Guard eBPF probes
    pub fn new(mode: GuardMode, json_output: bool) -> Result<Self> {
        Self::check_prerequisites()?;
        Self::bump_memlock_rlimit()?;

        info!("Loading minirun Guard eBPF skeleton (mode: {})...", mode);
        let builder = MinirunGuardSkelBuilder::default();
        let open_obj_box: &'static mut std::mem::MaybeUninit<libbpf_rs::OpenObject> =
            Box::leak(Box::new(std::mem::MaybeUninit::uninit()));
        let open_skel = builder.open(open_obj_box).context("Failed to open BPF skeleton")?;
        let mut loaded_skel = open_skel.load().context("Failed to load BPF bytecode and verifier pass")?;
        loaded_skel.attach().context("Failed to attach BPF tracepoint probes")?;

        // Leak skeleton to obtain a 'static reference for the background ringbuffer worker thread
        let skel: &'static MinirunGuardSkel<'static> = Box::leak(Box::new(loaded_skel));

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let killed_by_guard = Arc::new(AtomicBool::new(false));
        let container_cgroups = Arc::new(Mutex::new(HashMap::new()));

        let worker_shutdown = shutdown_flag.clone();
        let worker_killed = killed_by_guard.clone();
        let worker_containers = container_cgroups.clone();

        // Spawn background event processing thread
        let event_worker = std::thread::spawn(move || {
            let mut correlation = CorrelationEngine::new(Duration::from_secs(30));
            let mut rb_builder = libbpf_rs::RingBufferBuilder::new();

            let worker_containers_cb = worker_containers.clone();
            let worker_killed_cb = worker_killed.clone();
            let worker_containers_drops = worker_containers.clone();
            let worker_killed_drops = worker_killed.clone();

            rb_builder
                .add(&skel.maps.events, move |data: &[u8]| {
                    if data.len() < std::mem::size_of::<GuardEvent>() {
                        return 0;
                    }
                    // SAFETY: GuardEvent is #[repr(C)] matching the 336-byte BPF struct
                    let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const GuardEvent) };

                    handle_event(
                        &event,
                        mode,
                        json_output,
                        &mut correlation,
                        &worker_containers_cb,
                        &worker_killed_cb,
                    );
                    0
                })
                .expect("Failed to add events map to RingBufferBuilder");

            let ringbuf = match rb_builder.build() {
                Ok(rb) => rb,
                Err(e) => {
                    error!("Failed to build BPF ring buffer: {}", e);
                    return;
                }
            };

            info!("Guard telemetry worker running.");
            let mut last_drops: u64 = 0;

            let check_drops = |last_drops: &mut u64| {
                let current_drops = get_total_drops(&skel.maps.drops);
                let delta = current_drops.saturating_sub(*last_drops);
                if delta > 0 {
                    *last_drops = current_drops;
                    emit_drop_alert(
                        delta,
                        mode,
                        json_output,
                        &worker_containers_drops,
                        &worker_killed_drops,
                    );
                }
            };

            while !worker_shutdown.load(Ordering::Relaxed) {
                if let Err(e) = ringbuf.poll(Duration::from_millis(50)) {
                    debug!("Ring buffer poll returned: {}", e);
                }
                check_drops(&mut last_drops);
            }

            // DRAIN: after shutdown is signaled, make multiple poll/consume passes to guarantee
            // short-lived process events (e.g. cat /etc/shadow) and final kills are processed.
            let drain_start = Instant::now();
            while drain_start.elapsed() < Duration::from_millis(150) {
                let _ = ringbuf.poll(Duration::from_millis(20));
            }
            let _ = ringbuf.consume();
            check_drops(&mut last_drops);
        });

        Ok(Self {
            mode,
            json_output,
            skel,
            shutdown_flag,
            event_worker: Some(event_worker),
            container_cgroups,
            killed_by_guard,
        })
    }

    /// Register container cgroup in eBPF map before container processes are spawned
    pub fn register_container(&mut self, cgroup_path: &Path, container_id: &str) -> Result<u64> {
        let stat_info = nix::sys::stat::stat(cgroup_path)
            .with_context(|| format!("Failed to stat cgroup directory at {:?}", cgroup_path))?;
        let cgroup_id = stat_info.st_ino as u64;

        let mode_u32 = match self.mode {
            GuardMode::None => 0,
            GuardMode::Audit => 1,
            GuardMode::Enforce => 2,
        };

        let cfg = CgroupConfig {
            container_idx: 0,
            mode: mode_u32,
            flags: 0,
        };

        let key = cgroup_id.to_ne_bytes();
        // SAFETY: CgroupConfig is repr(C) POD struct
        let val = unsafe {
            std::slice::from_raw_parts(
                &cfg as *const CgroupConfig as *const u8,
                std::mem::size_of::<CgroupConfig>(),
            )
        };

        self.skel
            .maps
            .container_cgroups
            .update(&key, val, libbpf_rs::MapFlags::ANY)
            .context("Failed to insert cgroup ID into BPF container_cgroups map")?;

        let mut map = self.container_cgroups.lock().unwrap();
        map.insert(cgroup_id, (container_id.to_string(), cgroup_path.to_path_buf()));

        info!(
            "Registered container '{}' (cgroup id: {}) in Guard eBPF filter (mode: {})",
            container_id, cgroup_id, self.mode
        );
        Ok(cgroup_id)
    }

    /// Unregister container cgroup and clean up map entry on container termination
    pub fn unregister_container(&mut self, cgroup_id: u64) -> Result<()> {
        let key = cgroup_id.to_ne_bytes();
        let _ = self.skel.maps.container_cgroups.delete(&key);

        let mut map = self.container_cgroups.lock().unwrap();
        map.remove(&cgroup_id);
        debug!("Unregistered cgroup ID {} from Guard BPF map", cgroup_id);
        Ok(())
    }

    /// Shutdown event listener worker cleanly
    pub fn shutdown(&mut self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
        if let Some(worker) = self.event_worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        let cgroups: Vec<u64> = {
            if let Ok(map) = self.container_cgroups.lock() {
                map.keys().copied().collect()
            } else {
                Vec::new()
            }
        };
        for cgid in cgroups {
            let key = cgid.to_ne_bytes();
            let _ = self.skel.maps.container_cgroups.delete(&key);
        }
        self.shutdown();
    }
}

/*
 * ==============================================================================
 * Event Correlation & Threat Classification Dispatcher
 * ==============================================================================
 */

fn handle_event(
    event: &GuardEvent,
    mode: GuardMode,
    json_output: bool,
    correlation: &mut CorrelationEngine,
    containers: &Arc<Mutex<HashMap<u64, (String, PathBuf)>>>,
    killed_by_guard: &Arc<AtomicBool>,
) {
    let (container_id, cgroup_path) = {
        let map = containers.lock().unwrap();
        map.get(&event.cgroup_id)
            .cloned()
            .unwrap_or_else(|| (format!("unknown-{}", event.cgroup_id), PathBuf::new()))
    };

    let comm = bytes_to_str(&event.comm);
    let state = correlation.get_or_create(event.tgid, event.ppid);

    let mut emit_alert = false;
    let mut severity_str = severity_to_str(event.severity);
    let mut event_type_str = "EVENT".to_string();
    let mut details = String::new();

    match event.event_type {
        GUARD_EVENT_CONNECT => {
            // SAFETY: payload is union; read sock variant for connect
            let sock = unsafe { event.payload.sock };
            let target = format_sock_target(&sock);
            state.has_connected = true;
            state.connected_target = Some(target.clone());

            // Check if connection was to docker.sock (critical breakout)
            if sock.family == 1 && (event.flags & GUARD_FLAG_IN_KERNEL_KILL) != 0 {
                emit_alert = true;
                severity_str = "CRITICAL";
                event_type_str = "DOCKER_SOCK_CONNECT".to_string();
                details = format!("Attempted connect to docker socket: {}", target);
            } else if state.dup_fds.len() >= 2 && !state.reverse_shell_alerted {
                // Connect happened after stdin/stdout/stderr dup2 redirection!
                emit_alert = true;
                severity_str = "CRITICAL";
                event_type_str = "REVERSE_SHELL".to_string();
                state.reverse_shell_alerted = true;
                details = format!(
                    "reverse shell signature: connect {} with active stdin/out redirection (fds: {:?})",
                    target, state.dup_fds
                );
            } else {
                emit_alert = true;
                severity_str = "LOW";
                event_type_str = "OUTBOUND_CONNECT".to_string();
                details = format!("Attempted outbound connection to {}", target);
            }
        }
        GUARD_EVENT_DUP => {
            // SAFETY: payload is union; read dup variant for dup2/3
            let dup = unsafe { event.payload.dup };
            if state.dup_fds.len() < 16 {
                state.dup_fds.insert(dup.newfd);
            }

            // Check if process has already connected and now redirected 2+ standard fds
            if state.has_connected && state.dup_fds.len() >= 2 && !state.reverse_shell_alerted {
                emit_alert = true;
                severity_str = "CRITICAL";
                event_type_str = "REVERSE_SHELL".to_string();
                state.reverse_shell_alerted = true;
                let target = state.connected_target.as_deref().unwrap_or("unknown");
                details = format!(
                    "reverse shell sequence: connect {} -> dup2 onto fds {:?}",
                    target, state.dup_fds
                );
            }
        }
        GUARD_EVENT_OPENAT => {
            // SAFETY: payload is union; read path variant for open/openat
            let path_payload = unsafe { event.payload.path };
            let path = bytes_to_str(&path_payload.path);

            emit_alert = true;
            if (event.flags & GUARD_FLAG_IN_KERNEL_KILL) != 0 {
                severity_str = "CRITICAL";
                event_type_str = "CONTAINER_BREAKOUT".to_string();
                details = format!("Tampering with sensitive host target: {} (terminated in-kernel)", path);
            } else {
                severity_str = "HIGH";
                event_type_str = "SENSITIVE_FILE_ACCESS".to_string();
                details = format!("Accessed sensitive path: {} (flags: 0x{:x})", path, path_payload.flags);
            }
        }
        GUARD_EVENT_EXEC_RESOLVED => {
            // SAFETY: payload is union; read path variant for exec
            let path_payload = unsafe { event.payload.path };
            let path = bytes_to_str(&path_payload.path);

            if (event.flags & GUARD_FLAG_INIT_EXEC) != 0 {
                debug!("Container '{}' [PID {}] initial entrypoint executed: {}", container_id, event.pid, path);
            } else if state.has_connected && !state.dup_fds.is_empty() && is_shell(comm) {
                // Full sequence: connect -> dup2 -> exec shell
                emit_alert = true;
                severity_str = "CRITICAL";
                event_type_str = "REVERSE_SHELL".to_string();
                state.reverse_shell_alerted = true;
                let target = state.connected_target.as_deref().unwrap_or("unknown");
                details = format!("reverse shell sequence: connect {} -> dup2 -> {}", target, path);
            } else if event.severity >= GUARD_SEV_MEDIUM {
                emit_alert = true;
                severity_str = severity_to_str(event.severity);
                event_type_str = "SUSPICIOUS_EXEC".to_string();
                details = format!("Executed suspicious binary/shell: {} (comm: {})", path, comm);
            }
        }
        _ => {}
    }

    if emit_alert {
        let is_in_kernel_kill = (event.flags & GUARD_FLAG_IN_KERNEL_KILL) != 0;
        let is_enforced_violation = (severity_str == "CRITICAL") || is_in_kernel_kill;

        if is_in_kernel_kill {
            killed_by_guard.store(true, Ordering::SeqCst);
        }

        // ENFORCEMENT: Terminate container via cgroup.kill on CRITICAL or in-kernel kill
        let mut did_enforce = is_in_kernel_kill;
        if is_enforced_violation && mode == GuardMode::Enforce {
            did_enforce = true;
            killed_by_guard.store(true, Ordering::SeqCst);
            let kill_path = cgroup_path.join("cgroup.kill");
            if kill_path.exists() {
                if let Err(e) = fs::write(&kill_path, "1") {
                    error!("Guard enforce failed to write to {:?}: {}", kill_path, e);
                } else {
                    info!("Guard ENFORCE: Terminated container '{}' via {:?}", container_id, kill_path);
                }
            } else {
                warn!("Guard enforce: {:?} does not exist; killing PID {}", kill_path, event.pid);
                let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(event.pid as i32), nix::sys::signal::Signal::SIGKILL);
            }
        }

        if json_output {
            let alert = GuardAlert {
                timestamp: chrono::Utc::now().to_rfc3339(),
                container_id: container_id.clone(),
                pid: event.pid,
                tgid: event.tgid,
                ppid: event.ppid,
                comm: comm.to_string(),
                severity: severity_str.to_string(),
                event_type: event_type_str,
                details: details.clone(),
                enforced: did_enforce,
            };
            if let Ok(json_str) = serde_json::to_string(&alert) {
                println!("{}", json_str);
            }
        } else {
            let enforce_tag = if did_enforce { " [ENFORCED: KILLED]" } else { "" };
            println!(
                "[GUARD ALERT] [{}] [Container: {}] [PID: {}] [comm: {}] {}{}",
                severity_str, container_id, event.pid, comm, details, enforce_tag
            );
        }
    }
}

/*
 * ==============================================================================
 * Helpers
 * ==============================================================================
 */

fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor_str = parts.next()?;
    let minor = minor_str.split(|c: char| !c.is_ascii_digit()).next()?.parse::<u32>().ok()?;
    Some((major, minor))
}

fn bytes_to_str(buf: &[u8]) -> &str {
    let nul_pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..nul_pos]).unwrap_or("<invalid utf8>")
}

fn severity_to_str(sev: u32) -> &'static str {
    match sev {
        GUARD_SEV_INFO => "INFO",
        GUARD_SEV_LOW => "LOW",
        GUARD_SEV_MEDIUM => "MEDIUM",
        GUARD_SEV_HIGH => "HIGH",
        GUARD_SEV_CRITICAL => "CRITICAL",
        _ => "UNKNOWN",
    }
}

fn is_shell(comm: &str) -> bool {
    matches!(comm, "sh" | "bash" | "dash" | "ash" | "zsh")
}

fn format_sock_target(sock: &GuardSockPayload) -> String {
    match sock.family {
        2 => {
            let ip = Ipv4Addr::from(u32::from_be(sock.daddr_v4));
            let port = u16::from_be(sock.dport);
            format!("{}:{}", ip, port)
        }
        10 => {
            let ip = Ipv6Addr::from(sock.daddr_v6);
            let port = u16::from_be(sock.dport);
            format!("[{}]:{}", ip, port)
        }
        1 => {
            let path = bytes_to_str(&sock.sun_path);
            format!("unix:{}", path)
        }
        _ => format!("family:{}", sock.family),
    }
}

fn get_total_drops(map: &libbpf_rs::Map) -> u64 {
    let zero = 0u32.to_ne_bytes();
    if let Ok(Some(bytes)) = map.lookup(&zero, libbpf_rs::MapFlags::ANY) {
        let chunk_size = std::mem::size_of::<u64>();
        let mut total = 0u64;
        for chunk in bytes.chunks_exact(chunk_size) {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(chunk);
            total = total.saturating_add(u64::from_ne_bytes(arr));
        }
        total
    } else {
        0
    }
}

fn emit_drop_alert(
    dropped_count: u64,
    mode: GuardMode,
    json_output: bool,
    containers: &Arc<Mutex<HashMap<u64, (String, PathBuf)>>>,
    killed_by_guard: &Arc<AtomicBool>,
) {
    let container_info: Vec<(String, PathBuf)> = {
        let map = containers.lock().unwrap();
        map.values().cloned().collect()
    };

    let details = format!("Guard blind: {} events dropped due to ring buffer saturation", dropped_count);
    let mut did_enforce = false;

    // In enforce mode, a blinded monitor must fail closed!
    if mode == GuardMode::Enforce {
        did_enforce = true;
        killed_by_guard.store(true, Ordering::SeqCst);
        for (c_id, cg_path) in &container_info {
            let kill_path = cg_path.join("cgroup.kill");
            if kill_path.exists() {
                let _ = fs::write(&kill_path, "1");
                info!("Guard ENFORCE (fail-closed): Terminated container '{}' on ring buffer saturation", c_id);
            }
        }
    }

    if json_output {
        for (c_id, _) in &container_info {
            let alert = GuardAlert {
                timestamp: chrono::Utc::now().to_rfc3339(),
                container_id: c_id.clone(),
                pid: 0,
                tgid: 0,
                ppid: 0,
                comm: "kernel-ringbuf".to_string(),
                severity: "CRITICAL".to_string(),
                event_type: "RINGBUF_DROPS".to_string(),
                details: details.clone(),
                enforced: did_enforce,
            };
            if let Ok(json_str) = serde_json::to_string(&alert) {
                println!("{}", json_str);
            }
        }
    } else {
        let enforce_suffix = if did_enforce { " [ENFORCED: KILLED]" } else { "" };
        let cid_str = container_info.first().map(|(c, _)| format!("[Container: {}] ", c)).unwrap_or_default();
        println!(
            "[GUARD ALERT] [CRITICAL] {}[PID: 0] [comm: kernel-ringbuf] {}{}",
            cid_str,
            details,
            enforce_suffix
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guard_event_struct_size() {
        assert_eq!(
            std::mem::size_of::<GuardEvent>(),
            336,
            "GuardEvent struct size must match the 336-byte C BPF struct"
        );
    }

    #[test]
    fn test_kernel_version_parser() {
        assert_eq!(parse_kernel_version("5.14.0-generic"), Some((5, 14)));
        assert_eq!(parse_kernel_version("5.13.1"), Some((5, 13)));
        assert_eq!(parse_kernel_version("6.8.0-45-generic"), Some((6, 8)));
        assert_eq!(parse_kernel_version("7.2.11-arch1-1"), Some((7, 2)));
    }

    #[test]
    fn test_correlation_inheritance() {
        let mut engine = CorrelationEngine::new(Duration::from_secs(10));
        // Parent process (tgid: 100, ppid: 1) connects to a target
        let parent = engine.get_or_create(100, 1);
        parent.has_connected = true;
        parent.connected_target = Some("10.0.0.1:4444".to_string());
        parent.dup_fds.insert(0);
        parent.dup_fds.insert(1);

        // Child process (tgid: 101, ppid: 100) spawned by parent inherits state
        let child = engine.get_or_create(101, 100);
        assert!(child.has_connected);
        assert_eq!(child.connected_target.as_deref(), Some("10.0.0.1:4444"));
        assert!(child.dup_fds.contains(&0));
        assert!(child.dup_fds.contains(&1));
    }

    #[test]
    fn test_correlation_bounded_capacity() {
        let mut engine = CorrelationEngine::new(Duration::from_secs(60));
        // Fill up to max capacity + 10 entries
        for i in 0..(MAX_CORRELATION_STATES + 10) as u32 {
            let _ = engine.get_or_create(i, 0);
        }
        assert!(engine.states.len() <= MAX_CORRELATION_STATES);
    }
}
