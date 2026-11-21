# minirun v0.1.0 Release Notes

**minirun** is an educational, OCI-style Linux container runtime and runtime security engine written from scratch in Rust using direct POSIX syscalls, modern Cgroups v2 controllers, pure-Rust Seccomp-BPF filtering, and CO-RE eBPF active defense.

> [!NOTE]
> **Educational & Research Sandbox:** `minirun` is designed to demonstrate low-level container primitives and active kernel-level security telemetry from first principles. It is not intended as a production multi-tenant isolation engine.

---

## Highlights & Features

### 1. Linux Namespace Isolation
- **PID**: Container process executes as true `PID 1` inside an isolated process hierarchy via double-fork architecture.
- **Mount (MNT)**: Private mount table (`MS_REC | MS_PRIVATE`) preventing mount leaks to host.
- **UTS**: Isolated container hostname configuration.
- **IPC**: Isolated System V IPC and POSIX message queues.
- **Network (NET)**: Dedicated network namespace.
- **User (USER)**: Rootless execution mapping container `UID 0 (root)` to unprivileged host UID via `/proc/<pid>/uid_map` and `/proc/<pid>/gid_map`.

### 2. Cgroups v2 Resource Governance
- Memory ceiling (`memory.max`) with human-friendly units (`128M`, `1G`).
- CPU quota (`cpu.max`) with CFS bandwidth enforcement.
- Process limits (`pids.max`) providing anti-forkbomb protection.

### 3. Pure-Rust Seccomp-BPF Sandboxing
- Compiled via `seccompiler v0.5.0` directly into classic BPF bytecode (`SECCOMP_SET_MODE_FILTER`).
- **Default Denylist Profile (`--seccomp default`):** Rejects `ptrace`, `unshare`, `setns`, `bpf`, `mount`, `umount2`, `open_by_handle_at`, `kexec_load`, `reboot`, `init_module`, and the new Linux mount API (`fsopen`, `fsmount`, `open_tree`, `fsconfig`, etc.) with `EPERM`.
- **`clone` Argument Inspection:** Uses `MaskedEq` on `arg0` flags to selectively deny `CLONE_NEW*` namespace creation while permitting multi-threading (`pthread_create`) and normal process forks (`clone(SIGCHLD)`).
- **`clone3` Fallback Strategy:** Returns `ENOSYS` on `clone3` in default mode, enabling glibc and musl runtimes to fall back cleanly to `clone()` without sacrificing namespace boundary protections.
- **x32 ABI Protection:** Prepends a classic BPF prefix (`load nr -> jge 0x40000000 -> ret ENOSYS`) that neutralizes the `CONFIG_X86_X32_ABI` bypass on 64-bit systems.
- **Audit Mode (`--seccomp audit`):** Uses `SECCOMP_RET_LOG` to record violations in the kernel audit log (`dmesg` / `auditd`) without terminating or altering application control flow.
- **Conditional `PR_SET_NO_NEW_PRIVS`:** Enforced for rootless/non-root containers, while omitted for root containers with `CAP_SYS_ADMIN` so standard setuid tools (`ping`, `sudo`) function unless `--no-new-privs` is passed.

### 4. eBPF Guard: In-Kernel Active Defense & Telemetry
- **Kernel Tracepoints:** Hooks `sched_process_exec`, `sys_enter_execve`, `sys_enter_connect`, `sys_enter_openat*`, and `sys_enter_dup*` scoped strictly to the container cgroup hierarchy.
- **Lineage Correlation:** Real-time state machine correlating reverse-shell sequences (`connect(AF_INET/6) -> dup2(0,1,2) -> exec(shell)`) across parent-child lineages with TTL-bounded caching.
- **Active Enforcement (`--guard enforce`):** In-kernel SIGKILL boundaries (`docker.sock`, `core_pattern`) and userspace `cgroup.kill` termination (exit 137) on CRITICAL alerts.
- **Fail-Closed on Saturation:** Non-zero drop deltas in the 1 MiB ring buffer emit CRITICAL blindness alerts and trigger fail-closed termination under enforce mode.

### 5. Empirical Performance Overhead Benchmarking
- Multi-round benchmark suite measuring hooked `openat + close` and unhooked `getppid()` over 1,400,000 operations per condition:
  - **Baseline:** `openat+close` = 2,097.10 ns, `getppid` = 242.33 ns.
  - **Guard Loaded (Idle Host):** `openat+close` = 2,283.17 ns (+186.07 ns), `getppid` = 266.68 ns (+24.34 ns).
  - Isolates the global kernel syscall tracing entry tax (~24 ns) from probe execution cost (~162 ns).

---

## Verification & Test Coverage
- **Unit Tests:** 9/9 passing (`cargo test`).
- **Guard Integration Suite (`tests/test_guard.sh`):** 10 scenarios passing under `sudo` (benign commands, recon detection, network egress, reverse shell correlation, sensitive paths, enforce exemption, enforce termination).
- **Seccomp Integration Suite (`tests/test_seccomp.sh`):** 22 assertions passing under `sudo` (control assertions, denylist denials, multi-threading, pipelines, audit logging, strict rejection, rootless mode, and x32 mitigation).
- **Tested across both glibc and musl (Alpine Linux) runtimes.**
- **Mutation-Tested:** Proven to fail when `SYS_bpf` filter or `handle_sys_enter_connect` probe are disabled.
