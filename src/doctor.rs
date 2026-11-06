use anyhow::Result;
use std::fs;
use std::path::Path;

pub fn run_doctor() -> Result<()> {
    println!("=== minirun Linux Environment Diagnostics ===");

    // 1. Kernel Version
    let kernel = fs::read_to_string("/proc/version")
        .unwrap_or_else(|_| "Unknown".to_string());
    let first_line = kernel.lines().next().unwrap_or("Unknown");
    println!("  [✓] Kernel: {}", first_line);

    // 2. Cgroups v2 Check
    let cgroup2_controllers = Path::new("/sys/fs/cgroup/cgroup.controllers");
    if cgroup2_controllers.exists() {
        let controllers = fs::read_to_string(cgroup2_controllers).unwrap_or_default();
        println!("  [✓] Cgroups v2: Active (Available controllers: {})", controllers.trim());
    } else {
        println!("  [✗] Cgroups v2: Not mounted as unified hierarchy at /sys/fs/cgroup");
    }

    // 3. User Namespaces Support
    let userns_path = Path::new("/proc/sys/kernel/unprivileged_userns_clone");
    if userns_path.exists() {
        let enabled = fs::read_to_string(userns_path).unwrap_or_default();
        if enabled.trim() == "1" {
            println!("  [✓] Unprivileged User Namespaces: Enabled (Rootless supported)");
        } else {
            println!("  [!] Unprivileged User Namespaces: Disabled (Root required)");
        }
    } else {
        println!("  [✓] User Namespaces: Supported by kernel");
    }

    // 4. Linux Namespace Files in /proc/self/ns
    let ns_path = Path::new("/proc/self/ns");
    if ns_path.exists() {
        let mut supported_ns = Vec::new();
        for ns in &["pid", "mnt", "uts", "ipc", "net", "user", "cgroup"] {
            if ns_path.join(ns).exists() {
                supported_ns.push(*ns);
            }
        }
        println!("  [✓] Namespaces Supported: {}", supported_ns.join(", "));
    }

    // 5. Seccomp Support
    let status_path = Path::new("/proc/self/status");
    if let Ok(status) = fs::read_to_string(status_path) {
        if status.lines().any(|l| l.starts_with("Seccomp:")) {
            println!("  [✓] Seccomp BPF: Supported");
        } else {
            println!("  [!] Seccomp: Not detected in process status");
        }
    }

    println!("=============================================");
    Ok(())
}
