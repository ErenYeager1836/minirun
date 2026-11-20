# minirun Guard - Host Syscall Overhead Benchmark

This benchmark measures the host-side overhead imposed by `minirun Guard`'s eBPF tracepoint probes on non-container host processes.

## Test Methodology

The benchmark measures a tight loop of `openat(AT_FDCWD, "/dev/null", O_RDONLY)` followed by `close(fd)`. Using `/dev/null` isolates the pure VFS / syscall path and BPF probe execution from block device I/O latency.

We evaluate three conditions over **7 rounds of 200,000 iterations** each (1,400,000 iterations per condition), reporting median latency, mean, standard deviation, and min/max:
1. **Guard Unloaded (Baseline):** No BPF programs attached to the kernel.
2. **Guard Loaded (No Container Running):** Guard is loaded in `audit` mode with 8 tracepoint probes attached. Every host `openat` triggers `handle_sys_enter_openat`, performs `bpf_get_current_cgroup_id()`, looks up the `container_cgroups` hash map, and immediately returns 0.
3. **Guard Loaded (Busy Container Running):** Guard is active while a monitored container process in a dedicated cgroup continuously generates high-frequency syscalls into the BPF ring buffer.

## Environment

- **CPU:** 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz (4 cores / 8 threads)
- **Kernel Release:** `7.2.11-arch1-1` (x86_64, unified cgroups v2, BTF enabled)
- **Compiler:** `rustc 1.85+` (`cargo build --release`)

## Measured Results

| Condition | Median Latency | Mean ± StdDev | Min / Max | Overhead vs Baseline |
| :--- | :--- | :--- | :--- | :--- |
| **1. Guard Unloaded (Baseline)** | **2,268.96 ns** | 2,325.26 ± 128.55 ns | 2,149.69 / 2,540.62 ns | Baseline (0.00 ns) |
| **2. Guard Loaded (No Container)** | **2,743.05 ns** | 2,808.98 ± 254.21 ns | 2,483.34 / 3,198.35 ns | **+474.08 ns (+20.89%)** |
| **3. Guard Loaded (Busy Container)** | **3,301.53 ns** | 3,290.98 ± 191.41 ns | 3,015.24 / 3,611.93 ns | **+1,032.56 ns (+45.51%)** |

> **Syscall Cost Breakdown:**
> Because `minirun Guard` hooks `sys_enter_open`, `sys_enter_openat`, and `sys_enter_openat2` (but does not hook `close`), the +474 ns overhead in Condition 2 is attributable directly to the `openat` probe execution. On host non-container processes, the probe incurs approximately **~474 ns** for the tracepoint context switch, `bpf_get_current_cgroup_id()`, and the single BPF hash map lookup before early exit.
> Under heavy container contention (Condition 3), cache line and CPU core sharing increases host latency by an additional **~558 ns**.

## Running the Benchmark

The benchmark binary is built directly into the repository:

```bash
# Build optimized release binary
cargo build --release --bin guard_bench

# Run with root privileges (required for BPF tracepoint attachment)
sudo ./target/release/guard_bench
```
