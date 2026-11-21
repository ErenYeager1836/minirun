# minirun

[![CI](https://github.com/ErenYeager1836/minirun/actions/workflows/ci.yml/badge.svg)](https://github.com/ErenYeager1836/minirun/actions/workflows/ci.yml)

> [!NOTE]
> **Educational & Research Sandbox:** `minirun` is an educational container runtime and systems research sandbox designed to demonstrate container primitives and active eBPF defense from scratch. It is not intended as a production multi-tenant container isolation engine.

A from-scratch lightweight Linux container runtime written in **Rust** using direct POSIX and Linux kernel syscalls.

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
- **Seccomp-BPF Syscall Filtering**:
  - Granular in-kernel syscall restriction via pure Rust `seccompiler` (`--seccomp [default|strict|audit|none]`).
  - Default profile denylists dangerous syscalls (`ptrace`, `unshare`, `setns`, `bpf`, `mount`, new mount API, etc.).
  - Argument inspection on `clone` to block unauthorized namespace creation while permitting threading and subshells.
  - Transparent `clone3` fallback (`ENOSYS`) for glibc/musl compatibility.
  - Conditional `PR_SET_NO_NEW_PRIVS` flag (`--no-new-privs`).
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

### 5. Run with Seccomp-BPF Syscall Sandboxing
Apply in-kernel seccomp filters to restrict the container's attack surface against the host kernel:
```bash
# Default mode: Blocks dangerous syscalls with EPERM
sudo target/release/minirun run --seccomp default /bin/sh

# Audit mode: Logs attempted violations to kernel audit log (dmesg / journalctl) without blocking
sudo target/release/minirun run --seccomp audit /bin/sh

# Restrict privilege escalation via PR_SET_NO_NEW_PRIVS in root containers
sudo target/release/minirun run --seccomp default --no-new-privs /bin/sh
```

---

## eBPF Runtime Guard

`minirun Guard` is an in-kernel eBPF security telemetry and active defense engine. Standard container runtimes (like `runc`) isolate processes via namespaces and constrain resources via cgroups, but remain blind to malicious activity once execution begins. `Guard` bridges this gap with negligible overhead on non-container processes (restricted to `bpf_get_current_cgroup_id()` plus a single hash map lookup before early return).

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

### Performance & Host Syscall Overhead

Rather than claiming zero overhead, `minirun Guard` explicitly measures and bounds the CPU cost of its eBPF tracepoints on host processes. Activating tracepoints adds a general per-syscall tax across all host threads, plus a probe-specific execution cost on hooked syscalls.

Benchmarked on **11th Gen Intel Core i5-1135G7 @ 2.40GHz (Linux 7.2.11)** over 7 rounds of 200,000 iterations (1.4M operations per condition):

| Syscall Operation | Guard Unloaded (Baseline) | Guard Loaded (Idle Host) | Overhead (Tax) | Guard Loaded (Busy Container) |
| :--- | :--- | :--- | :--- | :--- |
| **openat + close** (hooked) | **2,097.10 ns** | **2,283.17 ns** | **+186.07 ns (+8.87%)** | **2,631.96 ns (+25.50%)** |
| **getppid** (unhooked) | **242.33 ns** | **266.68 ns** | **+24.34 ns (+10.04%)** | — |

- **General Syscall Tax (~24 ns):** Unhooked `getppid()` reflects the global kernel tracepoint activation tax across all processes.
- **Probe-Specific Cost (~162 ns):** Hooked `openat` incurs an additional ~162 ns for `bpf_get_current_cgroup_id()`, hash map lookup, and early return.
- **Container Load Delta (+534.85 ns - likely scheduling/CPU contention, not isolated):** Under active container load (Condition 3), latency increases to 2,631.96 ns. This delta is likely scheduling and CPU contention (cache evictions, turbo frequency adjustments, and runqueue pressure) rather than isolated BPF overhead. All benchmark metrics were measured on a single laptop CPU (11th Gen Intel i5-1135G7).

For complete methodology and reproduction commands, see [BENCHMARKS.md](file:///home/erenyeager/Projects/minirun/BENCHMARKS.md).

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

## Seccomp-BPF Syscall Filtering

`minirun` integrates kernel-level system call sandboxing via pure Rust BPF filter compilation (`seccompiler v0.5.0`). While eBPF Guard provides real-time detection and reactive termination, Seccomp-BPF enforces a preemptive kernel boundary directly at syscall entrypoints before any kernel state modifications take place.

### Isolation Modes (`--seccomp <mode>`)

1. **`default` (Recommended):**
   - Installs a strict denylist of hazardous kernel syscalls, returning `EPERM` (errno 1) on violation.
   - Enforces argument inspection on `clone` to prevent nested namespace creation.
   - Transparently handles modern thread creation via `clone3` fallback.
2. **`audit`:**
   - Observability mode that never blocks execution.
   - Sets the filter action to `SECCOMP_RET_LOG`, recording attempted violations in the host kernel audit log (`dmesg` / `journalctl -k`).
   - Omits the `clone3` filter to guarantee genuine observe-only behavior without altering application control flow.
3. **`strict`:**
   - Reserved for zero-trust application allowlisting.
   - Because generic container workloads require hundreds of baseline syscalls, `strict` mode currently fails closed with a descriptive `"not yet implemented"` error rather than shipping an insecure partial allowlist.
4. **`none`:**
   - Disables seccomp filtering entirely (default if flag is omitted).

### Default Denylist Coverage

| Category | Blocked Syscalls | Attack Mitigated |
| :--- | :--- | :--- |
| **Namespace Creation & Joining** | `unshare`, `setns` | Prevents unprivileged or root container processes from pivoting namespaces or joining host namespaces. |
| **Kernel Modification & Inspection** | `ptrace`, `kexec_load`, `kexec_file_load`, `reboot`, `init_module`, `finit_module`, `delete_module`, `bpf`, `keyctl`, `perf_event_open` | Blocks kernel module injection, BPF loading, host rebooting, cross-process tracing, and kernel key extraction. |
| **Legacy Filesystem Manipulation** | `mount`, `umount2`, `open_by_handle_at` | Blocks mounting arbitrary filesystems and prevents filesystem handle escapes (`open_by_handle_at`). |
| **New Linux Mount API** | `fsopen`, `fsmount`, `open_tree`, `fsconfig`, `fspick`, `move_mount`, `mount_setattr` | Prevents modern VFS mount table manipulation and unprivileged filesystem reconfiguration. |

### Argument Inspection: `clone` vs `clone3`

Container workloads (such as Python multi-threading, Go runtimes, or bash subshells) rely on `clone` for legitimate thread and process creation:
- **`clone` Filter:** Uses bitwise mask equality (`MaskedEq`) on `arg0` (`flags`) to deny invocations containing `CLONE_NEWNS`, `CLONE_NEWCGROUP`, `CLONE_NEWUTS`, `CLONE_NEWIPC`, `CLONE_NEWUSER`, `CLONE_NEWPID`, `CLONE_NEWNET`, or `CLONE_NEWTIME`. Invocations without namespace creation flags (such as `clone(SIGCHLD)` or `pthread_create`) are permitted.
- **`clone3` Strategy:** Modern glibc and musl runtimes attempt the `clone3` syscall by default. However, `clone3` passes its flags pointer in userspace memory (`struct clone_args`), which classic seccomp cannot inspect without deep BPF filtering. In `default` mode, `minirun` returns `ENOSYS` on `clone3`. Standard C libraries interpret `ENOSYS` as an unsupported kernel syscall and immediately fall back to classic `clone()`, allowing `minirun` to safely inspect namespace flags while preserving full multi-threading compatibility.

### Privileges & `NO_NEW_PRIVS`

Installing a Seccomp filter requires either `CAP_SYS_ADMIN` in the current user namespace or the `PR_SET_NO_NEW_PRIVS` bit set via `prctl`:
- **Rootless & Non-Root Execution:** `PR_SET_NO_NEW_PRIVS` is set automatically.
- **Privileged Root Containers:** In root containers with `CAP_SYS_ADMIN`, `PR_SET_NO_NEW_PRIVS` is omitted by default so that standard setuid utilities (such as `ping` or `sudo`) continue to function inside the container.
- **Explicit Flag (`--no-new-privs`):** Pass `--no-new-privs` to unconditionally lock down root containers against setuid privilege escalation.

### Threat Model & Limitations

* **Denylist vs. Allowlist Tradeoff:** Denylists are practical for general-purpose container runtimes to avoid breaking arbitrary userland tools, but allowlists provide strictly superior security by denying unknown syscalls by default.
* **x32 ABI Mitigation:** On x86_64 kernels where the x32 ABI is active at runtime, syscall numbers with bit 30 set (`0x40000000`) target the x32 ABI, which would otherwise bypass a 64-bit-only denylist. `minirun` prepends a classic BPF instruction prefix (`load nr -> jge 0x40000000 -> ret EPERM`) that intercepts x32-range syscalls at entry. On kernels where x32 is disabled at boot (`syscall.x32=off`), the kernel already returns `ENOSYS`; `minirun`'s filter explicitly enforces rejection with `EPERM` regardless of host boot parameters.
* **Audit Mode Log Routing:** Under `--seccomp audit`, violations route directly to the Linux kernel audit subsystem (`auditd` / `dmesg`), independent of Guard's eBPF ring buffer.
* **Capabilities vs. Seccomp:** Seccomp restricts syscall invocation, but does NOT replace Linux capability bounding set reduction (`cap_drop`). A root container retaining `CAP_SYS_ADMIN` with write access to host-shared pseudo-files (such as cgroup v1 `release_agent`) can achieve host escape via standard file operations without calling restricted syscalls. Capability bounding set dropping is tracked on the roadmap.

---

## License

This project is licensed under the terms of the [MIT License](LICENSE).
- Userspace container runtime and CLI tools: **MIT License**.
- In-kernel eBPF security telemetry programs (`bpf/minirun_guard.bpf.c`): **Dual MIT/GPL-2.0 License**.
- Generated kernel BTF bindings (`vmlinux.h`): Derived from the Linux kernel source tree (**GPL-2.0 with Linux-syscall-note**).
