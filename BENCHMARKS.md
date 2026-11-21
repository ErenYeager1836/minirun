# minirun Guard - Host Syscall Overhead Benchmark

This benchmark measures the host-side overhead imposed by `minirun Guard`'s eBPF tracepoint probes on non-container host processes.

## Test Methodology

The benchmark measures two distinct operations:
1. **Hooked Syscall Path:** A tight loop of `openat(AT_FDCWD, "/dev/null", O_RDONLY)` followed by `close(fd)`. Guard attaches to `sys_enter_open`, `sys_enter_openat`, and `sys_enter_openat2`.
2. **Unhooked Syscall Path:** A tight loop of raw `getppid()`, which is **never** hooked by Guard. This measures the baseline kernel-wide entry tax introduced whenever syscall tracepoints (`sys_enter_*`) are active in the kernel.

We evaluate three conditions over **7 rounds of 200,000 iterations** each (1,400,000 operations per condition), reporting median latency, mean, standard deviation, and min/max:
- **Condition 1 (Guard Unloaded - Baseline):** No BPF programs attached to the kernel.
- **Condition 2 (Guard Loaded - Idle Host):** Guard is loaded in `audit` mode with 8 tracepoint probes attached. Every host `openat` triggers `handle_sys_enter_openat`, performs `bpf_get_current_cgroup_id()`, looks up the `container_cgroups` hash map, and immediately returns 0.
- **Condition 3 (Guard Loaded - Busy Container):** Guard is active while a monitored container process in a dedicated cgroup continuously generates high-frequency syscalls into the BPF ring buffer.

## Environment

- **CPU:** 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz (4 physical cores / 8 threads)
- **Kernel Release:** `7.2.11-arch1-1` (x86_64, unified cgroups v2, BTF enabled)
- **Compiler:** `rustc 1.85+` (`cargo build --release`)

## Measured Results

| Syscall Operation | Guard Unloaded (Baseline) | Guard Loaded (Idle Host) | Guard Overhead (Tax) | Guard Loaded (Busy Container) |
| :--- | :--- | :--- | :--- | :--- |
| **openat + close** (hooked) | **2,097.10 ns** | **2,283.17 ns** | **+186.07 ns (+8.87%)** | **2,631.96 ns (+25.50%)** |
| **getppid** (unhooked) | **242.33 ns** | **266.68 ns** | **+24.34 ns (+10.04%)** | — |

## Syscall Cost Breakdown & Attribution

Rather than making an unsupported "zero overhead" claim, empirical separation reveals two distinct overhead components:

1. **General Kernel Syscall Tax (~24 ns):**
   The unhooked `getppid()` syscall exhibits a **+24.34 ns** increase when Guard is loaded. In Linux, enabling any `sys_enter_*` tracepoint activates the kernel's slower syscall tracing entry path across all threads. Guard introduces a modest ~10% global baseline tax on all syscalls.
2. **Specific Probe Overhead (~162 ns):**
   On `openat + close`, the total overhead is **+186.07 ns**. Subtracting the general syscall entry tax of ~24 ns per syscall yields approximately **~162 ns** of probe-specific execution cost. This represents the CPU time required for the BPF tracepoint context switch, executing `bpf_get_current_cgroup_id()`, querying the BPF hash map, and returning early.
3. **Container Load Delta (+534.85 ns - likely scheduling/CPU contention, not isolated):**
   When a container runs a continuous syscall flood (Condition 3), host `openat + close` latency increases to 2,631.96 ns (+534.85 ns over baseline). This delta is likely scheduling and CPU contention (cache evictions, turbo frequency adjustments, and runqueue pressure) rather than isolated BPF overhead, as host threads compete with container workloads. Note: All figures were measured on a single laptop CPU (11th Gen Intel i5-1135G7) under specific thermal and power conditions.

## Running the Benchmark

The benchmark binary is built directly into the repository:

```bash
# Build optimized release binary
cargo build --release --bin guard_bench

# Run with root privileges (required for BPF tracepoint attachment)
sudo ./target/release/guard_bench
```
