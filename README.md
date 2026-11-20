# minirun

An OCI-style lightweight Linux container runtime written from scratch in **Rust** using direct POSIX and Linux kernel syscalls.

`minirun` demonstrates how containerization works under the hood without relying on Docker, containerd, runc, or any external runtime daemon.

---

## Features

- **Linux Namespace Isolation**:
  - `PID`: Container process runs as `PID 1` inside an isolated process hierarchy.
  - `Mount (MNT)`: Private mount table (`MS_REC | MS_PRIVATE`) preventing mount leaks to host.
  - `UTS`: Custom isolated container hostname.
  - `IPC`: Isolated System V IPC and POSIX message queues.
  - `Network (NET)`: Isolated network namespace.
  - `User (USER)`: **Rootless execution** mapping container `UID 0 (root)` to unprivileged host user via `/proc/<pid>/uid_map` and `/proc/<pid>/gid_map`.
- **Cgroups v2 Resource Enforcement**:
  - Memory ceiling (`memory.max`) with human-friendly parsing (`128M`, `1G`).
  - CPU quota (`cpu.max`) with CFS bandwidth control.
  - Process limits (`pids.max`) to prevent fork bombs.
- **Rootfs Sandboxing (`pivot_root`)**:
  - Bind mounts rootfs onto itself.
  - Uses `pivot_root` to swap host root with container rootfs, detaching the old root via `MNT_DETACH`.
  - Mounts isolated virtual pseudo-filesystems (`/proc`, read-only `/sys`).
- **Runtime Diagnostics (`minirun doctor`)**:
  - Inspects kernel version, cgroups v2 controllers, user namespace support, and seccomp capability.

---

## Architecture

```text
minirun (Host Process)
  │
  ├── 1. Fork container process
  │     ├── Child unshares CLONE_NEWUSER (if --rootless)
  │     └── Child notifies parent via pipe
  │
  ├── 2. Parent (Host Namespace)
  │     ├── Writes /proc/<child>/setgroups -> 'deny'
  │     ├── Writes /proc/<child>/uid_map -> '0 <host_uid> 1'
  │     ├── Writes /proc/<child>/gid_map -> '0 <host_gid> 1'
  │     ├── Attaches child to /sys/fs/cgroup/minirun/<id>
  │     └── Signals child via pipe
  │
  └── 3. Child (Container Process)
        ├── Unshares CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET
        ├── Sub-forks to become true PID 1 inside new PID namespace
        ├── Sets container hostname
        ├── pivot_root into rootfs (or mounts private /proc)
        └── execvp(<command>, <args>)
```

---

## Quick Start

### 1. Check System Capabilities
```bash
cargo run -- doctor
```

### 2. Run Rootless Container
Run an isolated process as container PID 1 without needing `sudo`:
```bash
# Verify PID isolation (inside the container, it is PID 1)
cargo run -- run --rootless sh -- -c 'echo "My container PID is: $$"'

# Verify UTS hostname isolation
cargo run -- run --rootless --hostname sandbox uname -- -n

# Verify User Namespace mapping (UID 0 inside container)
cargo run -- run --rootless id
```

### 3. Run with Cgroup Resource Limits
```bash
sudo target/release/minirun run \
  --memory 128M \
  --cpus 1.0 \
  --pids 50 \
  --hostname isolated-box \
  /bin/sh
```

### 4. Run with eBPF Runtime Security Guard
Attach real-time eBPF kernel monitors scoped strictly to the container cgroup hierarchy:
```bash
# Audit mode: Stream real-time telemetry and alerts without terminating processes
sudo target/debug/minirun run --guard audit /bin/sh

# Enforce mode: Automatically terminate the container via cgroup.kill on CRITICAL violations
sudo target/debug/minirun run --guard enforce /bin/sh

# Structured JSON output for SIEM/logging pipelines
sudo target/debug/minirun run --guard audit --guard-json /bin/sh
```

---

## eBPF Runtime Guard

`minirun Guard` is an in-kernel eBPF security telemetry and active defense engine. Standard container runtimes (like `runc`) isolate processes via namespaces and constrain resources via cgroups, but remain blind to malicious activity once execution begins. `Guard` bridges this gap with zero overhead for the rest of the host.

### Architecture

```text
[ Kernel Space ]
  tracepoint/sched/sched_process_exec ──┐
  tracepoint/syscalls/sys_enter_execve ─┤
  tracepoint/syscalls/sys_enter_connect ┼─> [bpf_get_current_cgroup_id()] ──> container_cgroups map?
  tracepoint/syscalls/sys_enter_open* ──┤                                          │ (Match: Send event)
  tracepoint/syscalls/sys_enter_dup2/3 ─┘                                          ▼
                                                                           [ 1 MiB Ring Buffer ]
                                                                                   │
[ Userspace (Parent Runtime) ]                                                     │
  Guard Telemetry Thread <─────────────────────────────────────────────────────────┘
    ├── Correlation Engine (tgid + ppid lineage with TTL)
    │     ├── connect -> dup2(0,1,2) -> exec(shell) => [CRITICAL] Reverse Shell
    │     ├── Heuristic Classifier (recon tools, staging dirs, sensitive paths)
    │     └── Sensitive Access (/etc/shadow, core_pattern, docker.sock)
    └── Active Enforcement (Enforce Mode)
          └── Writes "1" to <cgroup>/cgroup.kill -> Container exits with status 137
```

### Probes & Detection Scope

1. **Sched & Exec (`sched_process_exec`, `sys_enter_execve`):**
   - Tracks executed binaries, paths, and comm names.
   - Initial entrypoint exemption: if the container is launched with `/bin/sh` or `/bin/bash`, the initial execution is classified as `INFO` and exempt from enforcement.
   - Heuristics: flags subsequent interactive shells (`sh`, `bash`, `dash`, `ash`, `zsh`) as `HIGH`, recon binaries (`nc`, `ncat`, `curl`, `wget`, `whoami`) and staging directory runs (`/tmp`, `/dev/shm`, `/var/tmp`) as `MEDIUM`. `busybox` is evaluated as `MEDIUM` at most to prevent false alerts on standard Alpine Linux commands.
2. **Network Egress (`sys_enter_connect`):**
   - Tracks outbound socket connection attempts across `AF_INET` (IPv4:port), `AF_INET6` (IPv6:port), and `AF_UNIX` (path).
   - Unambiguous breakout: attempts to connect to host `/run/docker.sock` or `/var/run/docker.sock` are flagged as `CRITICAL` and killed in-kernel.
3. **Sensitive File Access (`sys_enter_open`, `sys_enter_openat`, `sys_enter_openat2`):**
   - Shared in-kernel prefix filter inspecting only high-risk paths:
     - `/etc/shadow`, `/etc/sudoers` $\rightarrow$ `HIGH` (credential & privilege escalation access).
     - `/proc/1/root` $\rightarrow$ `HIGH` (container's own root view in isolated PID namespace).
     - `/run/docker.sock`, `/var/run/docker.sock` $\rightarrow$ `CRITICAL` (container breakout).
     - `/proc/sys/kernel/core_pattern` $\rightarrow$ `CRITICAL` on write intent (`(flags & 3) != 0`), `HIGH` on read.
   - All non-sensitive file opens are dropped in-kernel immediately with zero ring buffer traffic.
4. **File Descriptor Redirection (`sys_enter_dup2`, `sys_enter_dup3`):**
   - Emits events when `newfd` is 0 (stdin), 1 (stdout), or 2 (stderr).
5. **Reverse Shell Correlation:**
   - Detects the classic reverse-shell sequence: `connect(AF_INET/6) -> dup2(0,1,2) -> exec(shell)` across process lineages via `ppid` inheritance.
   - Also flags processes that connect after stdin/stdout/stderr have already been redirected (pre-spawned shell).

### Host PID Semantics
All `pid`, `tgid`, and `ppid` values reported in Guard alerts represent **host-namespace PIDs** (from `bpf_get_current_pid_tgid()` and `real_parent->tgid`), NOT virtualized PIDs inside the container's PID namespace (where the root process is PID 1). Userspace can directly correlate these PIDs against `/sys/fs/cgroup/minirun/<id>/cgroup.procs`.

### Alert Output Formats

#### Human-Readable Console Output:
```text
[GUARD ALERT] [CRITICAL] [Container: minirun-1042] [PID: 2841] [comm: python3] reverse shell sequence: connect 10.0.0.1:4444 -> dup2 -> /bin/sh [ENFORCED: KILLED]
[GUARD ALERT] [HIGH] [Container: minirun-1042] [PID: 2845] [comm: cat] Accessed sensitive path: /etc/shadow (flags: 0x0)
```

#### JSON Lines Format (`--guard-json`):
```json
{"timestamp":"2026-11-19T21:46:00Z","container_id":"minirun-1042","pid":2841,"tgid":2841,"ppid":2800,"comm":"python3","severity":"CRITICAL","event_type":"REVERSE_SHELL","details":"reverse shell sequence: connect 10.0.0.1:4444 -> dup2 -> /bin/sh","enforced":true}
```

### Threat Model & Limitations

* **Root Privileges Required:** Guard requires `CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_RESOURCE` (or root) to load eBPF programs, attach to tracepoints, and configure cgroup controllers.
* **Kernel Prerequisites:** Requires Linux kernel 5.14+ with BTF support enabled (`/sys/kernel/btf/vmlinux`) and unified cgroups v2 (`/sys/fs/cgroup/cgroup.controllers`).
* **TOCTOU on User Pointers:** User-space pointer reads (via `bpf_probe_read_user_str`) in `sys_enter_*` tracepoints are subject to Time-Of-Check to Time-Of-Use races if an attacker concurrently modifies memory from another thread. These probes provide high-fidelity runtime telemetry and heuristics, not a hard security perimeter (a hard boundary requires BPF LSM).
* **Heuristic Evasions:** Command name (`comm`) and binary name lists (`nc`, `curl`, etc.) are heuristic indicators and can be circumvented by renaming or symlinking binaries.
* **Best-Effort Enforcement:** In-kernel `bpf_send_signal(SIGKILL)` and userspace `cgroup.kill` take effect upon return to userspace; enforcement kills after the syscall completes, meaning the triggering syscall may complete prior to process termination. Tracepoint-based enforcement cannot block a syscall prior to execution (a preemptive boundary requires BPF LSM).
* **Abstract Unix Sockets:** Abstract AF_UNIX sockets (with a leading NUL byte) read as empty strings and are not matched by path filters.
* **PID Reuse within TTL:** Process correlation state persists for up to 30 seconds (`TTL`). In high-churn environments with low host `pid_max`, a recycled PID could theoretically inherit a prior process's `has_connected` state. On systems with standard 32-bit or high `pid_max` (typically 4,194,304), this race is negligible.
* **Ring Buffer Saturation & Fail-Closed Defense:** If an attacker attempts to blind Guard by flooding events, failed reservations increment a per-CPU `drops` counter. When userspace detects a non-zero drop delta, it emits a `CRITICAL` alert (`Guard blind: N events dropped`). In enforce mode, Guard treats telemetry blindness as a security breach and fails closed by terminating the container via `cgroup.kill`. Additionally, in-kernel SIGKILL boundaries (`docker.sock` and `core_pattern`) evaluate and dispatch signals before `reserve_event()`, preventing flood-based evasion.

---

## License
MIT
