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

---

## License
MIT
