use anyhow::{Context, Result};
use minirun::cgroups::CgroupV2Manager;
use minirun::guard::{Guard, GuardMode};
use nix::sys::utsname::uname;
use std::ffi::CString;
use std::fs;
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone)]
struct RunStats {
    _name: String,
    _samples: Vec<f64>, // nanoseconds per openat+close operation
    min: f64,
    median: f64,
    max: f64,
    mean: f64,
    std_dev: f64,
}

impl RunStats {
    fn new(name: &str, mut samples: Vec<f64>) -> Self {
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let count = samples.len() as f64;
        let min = samples.first().copied().unwrap_or(0.0);
        let max = samples.last().copied().unwrap_or(0.0);
        let median = if samples.len() % 2 == 1 {
            samples[samples.len() / 2]
        } else {
            let mid = samples.len() / 2;
            (samples[mid - 1] + samples[mid]) / 2.0
        };
        let mean = samples.iter().sum::<f64>() / count;
        let variance = samples.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / count;
        let std_dev = variance.sqrt();

        Self {
            _name: name.to_string(),
            _samples: samples,
            min,
            median,
            max,
            mean,
            std_dev,
        }
    }
}

/// Measures the average latency (in nanoseconds) per openat() + close() pair.
fn measure_openat_close(path: &CString, iterations: usize) -> f64 {
    let mut successes = 0usize;
    let start = Instant::now();

    for _ in 0..iterations {
        // SAFETY: path is a valid null-terminated C string pointing to /dev/null
        let fd = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                path.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if fd >= 0 {
            successes += 1;
            unsafe {
                libc::close(fd);
            }
        }
    }

    let elapsed = start.elapsed();
    black_box(successes);

    (elapsed.as_nanos() as f64) / (iterations as f64)
}

fn benchmark_condition(name: &str, rounds: usize, iterations_per_round: usize) -> RunStats {
    let path = CString::new("/dev/null").expect("valid CString");

    // Warmup round to stabilize CPU frequency scaling and L1 instruction caches
    measure_openat_close(&path, 50_000);

    let mut samples = Vec::with_capacity(rounds);
    for r in 1..=rounds {
        let latency = measure_openat_close(&path, iterations_per_round);
        println!("  [Round {}/{}] {:.2} ns / (openat + close)", r, rounds, latency);
        samples.push(latency);
    }

    RunStats::new(name, samples)
}

fn get_cpu_model() -> String {
    if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
        for line in content.lines() {
            if line.starts_with("model name") {
                if let Some(pos) = line.find(':') {
                    return line[pos + 1..].trim().to_string();
                }
            }
        }
    }
    "Unknown CPU".to_string()
}

fn main() -> Result<()> {
    println!("==============================================================================");
    println!(" minirun Guard - Host Syscall Overhead Benchmark");
    println!("==============================================================================");

    let kernel_release = uname()?.release().to_string_lossy().to_string();
    let cpu_model = get_cpu_model();
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    println!("Hardware & Kernel Environment:");
    println!("  CPU: {} ({} logical cores)", cpu_model, num_cpus);
    println!("  Kernel Release: {}", kernel_release);
    println!("==============================================================================");

    let is_root = nix::unistd::getuid().is_root();
    if !is_root {
        eprintln!("WARNING: Benchmarking Guard loaded states requires root (sudo) for BPF tracepoint attachment.");
        eprintln!("Please run: sudo ./target/release/guard_bench");
        std::process::exit(1);
    }

    let rounds = 7;
    let iterations = 200_000;

    // -------------------------------------------------------------------------
    // Condition 1: Guard Unloaded (Baseline)
    // -------------------------------------------------------------------------
    println!("\n>>> Condition 1: Guard Unloaded (Baseline)");
    println!("Executing {} rounds of {} iterations...", rounds, iterations);
    let stats_unloaded = benchmark_condition("Guard Unloaded", rounds, iterations);
    println!(
        "-> Result: Median = {:.2} ns, Mean = {:.2} ns (±{:.2} ns), Min = {:.2} ns, Max = {:.2} ns",
        stats_unloaded.median, stats_unloaded.mean, stats_unloaded.std_dev, stats_unloaded.min, stats_unloaded.max
    );

    // -------------------------------------------------------------------------
    // Condition 2: Guard Loaded (No Container Running)
    // -------------------------------------------------------------------------
    println!("\n>>> Condition 2: Guard Loaded (No Container Running)");
    println!("Loading Guard eBPF skeleton (audit mode) and attaching 8 tracepoint probes...");
    let mut guard = Guard::new(GuardMode::Audit, false)
        .context("Failed to load and attach Guard eBPF probes")?;
    println!("Guard attached. Executing {} rounds on the host (early cgroup filter exit)...", rounds);
    let stats_loaded_idle = benchmark_condition("Guard Loaded (Idle)", rounds, iterations);
    println!(
        "-> Result: Median = {:.2} ns, Mean = {:.2} ns (±{:.2} ns), Min = {:.2} ns, Max = {:.2} ns",
        stats_loaded_idle.median, stats_loaded_idle.mean, stats_loaded_idle.std_dev, stats_loaded_idle.min, stats_loaded_idle.max
    );

    // -------------------------------------------------------------------------
    // Condition 3: Guard Loaded (Busy Container Running)
    // -------------------------------------------------------------------------
    println!("\n>>> Condition 3: Guard Loaded (Busy Container Generating High-Frequency Syscalls)");
    println!("Provisioning container cgroup and registering in Guard filter...");
    let bench_cgroup_id = format!("bench-busy-{}", std::process::id());
    let cgroup_mgr = CgroupV2Manager::new(&bench_cgroup_id)
        .context("Failed to create container cgroup for benchmark")?;
    let registered_cgid = guard
        .register_container(cgroup_mgr.cgroup_path(), &bench_cgroup_id)
        .context("Failed to register benchmark container in Guard map")?;

    let worker_running = Arc::new(AtomicBool::new(true));
    let worker_flag = worker_running.clone();
    let cgroup_path = cgroup_mgr.cgroup_path().to_path_buf();

    // Spawn a busy thread inside the container cgroup performing continuous openat/close
    let worker_handle = std::thread::spawn(move || {
        // Attach this worker thread to the monitored container cgroup
        let tid = nix::unistd::gettid().as_raw();
        let procs_file = cgroup_path.join("cgroup.procs");
        let _ = fs::write(procs_file, tid.to_string());

        let target_path = CString::new("/etc/hosts").unwrap();
        while worker_flag.load(Ordering::Relaxed) {
            for _ in 0..10_000 {
                let fd = unsafe {
                    libc::openat(
                        libc::AT_FDCWD,
                        target_path.as_ptr(),
                        libc::O_RDONLY | libc::O_CLOEXEC,
                    )
                };
                if fd >= 0 {
                    unsafe { libc::close(fd) };
                }
            }
            std::thread::yield_now();
        }
    });

    // Let the busy worker spin up and start generating events
    std::thread::sleep(std::time::Duration::from_millis(200));

    println!("Worker active in cgroup.procs. Executing {} rounds on the host...", rounds);
    let stats_loaded_busy = benchmark_condition("Guard Loaded (Busy Container)", rounds, iterations);
    println!(
        "-> Result: Median = {:.2} ns, Mean = {:.2} ns (±{:.2} ns), Min = {:.2} ns, Max = {:.2} ns",
        stats_loaded_busy.median, stats_loaded_busy.mean, stats_loaded_busy.std_dev, stats_loaded_busy.min, stats_loaded_busy.max
    );

    // Stop worker and clean up
    worker_running.store(false, Ordering::Relaxed);
    let _ = worker_handle.join();
    let _ = guard.unregister_container(registered_cgid);
    guard.shutdown();
    let _ = fs::remove_dir_all(cgroup_mgr.cgroup_path());

    // -------------------------------------------------------------------------
    // Analysis and Overhead Calculations
    // -------------------------------------------------------------------------
    let delta_idle = stats_loaded_idle.median - stats_unloaded.median;
    let pct_idle = (delta_idle / stats_unloaded.median) * 100.0;

    let delta_busy = stats_loaded_busy.median - stats_unloaded.median;
    let pct_busy = (delta_busy / stats_unloaded.median) * 100.0;

    println!("\n==============================================================================");
    println!(" BENCHMARK RESULTS SUMMARY (Medians over {} rounds of {} iterations)", rounds, iterations);
    println!("==============================================================================");
    println!("Platform: {} | Kernel: {}", cpu_model, kernel_release);
    println!("Operation: openat(AT_FDCWD, \"/dev/null\", O_RDONLY) + close(fd)\n");

    println!("| Condition | Median Latency | Mean ± StdDev | Overhead vs Baseline |");
    println!("| :--- | :--- | :--- | :--- |");
    println!(
        "| **1. Guard Unloaded (Baseline)** | **{:.2} ns** | {:.2} ± {:.2} ns | Baseline (0.00 ns) |",
        stats_unloaded.median, stats_unloaded.mean, stats_unloaded.std_dev
    );
    println!(
        "| **2. Guard Loaded (No Container)** | **{:.2} ns** | {:.2} ± {:.2} ns | **{:+.2} ns ({:+.2}%)** |",
        stats_loaded_idle.median, stats_loaded_idle.mean, stats_loaded_idle.std_dev, delta_idle, pct_idle
    );
    println!(
        "| **3. Guard Loaded (Busy Container)** | **{:.2} ns** | {:.2} ± {:.2} ns | **{:+.2} ns ({:+.2}%)** |",
        stats_loaded_busy.median, stats_loaded_busy.mean, stats_loaded_busy.std_dev, delta_busy, pct_busy
    );
    println!("==============================================================================");

    Ok(())
}
