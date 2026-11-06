use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

pub struct CgroupV2Manager {
    cgroup_path: PathBuf,
}

impl CgroupV2Manager {
    /// Creates a new cgroup v2 controller directory for the container
    pub fn new(container_id: &str) -> Result<Self> {
        let base_cgroup = Path::new("/sys/fs/cgroup");
        if !base_cgroup.join("cgroup.controllers").exists() {
            warn!("Cgroups v2 unified hierarchy not detected at /sys/fs/cgroup");
        }

        let cgroup_path = base_cgroup.join("minirun").join(container_id);
        if let Err(e) = fs::create_dir_all(&cgroup_path) {
            warn!("Failed to create system cgroup at {:?}: {}. Falling back to user scope.", cgroup_path, e);
            // Fallback for non-root users if system cgroup is read-only
            let uid = nix::unistd::getuid().as_raw();
            let user_cgroup = base_cgroup
                .join("user.slice")
                .join(format!("user-{}.slice", uid))
                .join("minirun")
                .join(container_id);
            fs::create_dir_all(&user_cgroup).with_context(|| {
                format!("Failed to create cgroup directory at {:?}", user_cgroup)
            })?;
            info!("Created user-scoped cgroup v2 at {:?}", user_cgroup);
            return Ok(Self { cgroup_path: user_cgroup });
        }

        info!("Created cgroup v2 at {:?}", cgroup_path);
        Ok(Self { cgroup_path })
    }

    /// Add a process PID to this cgroup
    pub fn add_process(&self, pid: i32) -> Result<()> {
        let procs_file = self.cgroup_path.join("cgroup.procs");
        debug!("Adding PID {} to cgroup {:?}", pid, procs_file);
        fs::write(&procs_file, pid.to_string())
            .with_context(|| format!("Failed to write PID {} to {:?}", pid, procs_file))?;
        Ok(())
    }

    /// Apply memory limit in bytes (e.g. from "128M", "1G")
    pub fn apply_memory_limit(&self, memory_str: &str) -> Result<()> {
        let bytes = parse_memory_to_bytes(memory_str)?;
        let mem_file = self.cgroup_path.join("memory.max");
        debug!("Writing memory limit {} bytes to {:?}", bytes, mem_file);
        fs::write(&mem_file, bytes.to_string())
            .with_context(|| format!("Failed to set memory.max at {:?}", mem_file))?;
        info!("Enforced memory limit: {} ({} bytes)", memory_str, bytes);
        Ok(())
    }

    /// Apply CPU quota as fraction of cores (e.g. 0.5 cores -> 50000 100000)
    pub fn apply_cpu_limit(&self, cpus: f64) -> Result<()> {
        if cpus <= 0.0 {
            anyhow::bail!("CPU quota must be positive, got: {}", cpus);
        }
        let period: u64 = 100_000; // default 100ms CFS period
        let quota: u64 = (cpus * period as f64) as u64;
        let cpu_file = self.cgroup_path.join("cpu.max");
        let payload = format!("{} {}", quota, period);
        debug!("Writing cpu.max '{}' to {:?}", payload, cpu_file);
        fs::write(&cpu_file, payload)
            .with_context(|| format!("Failed to set cpu.max at {:?}", cpu_file))?;
        info!("Enforced CPU quota: {:.2} cores ({}us / {}us)", cpus, quota, period);
        Ok(())
    }

    /// Apply max PIDs limit to prevent fork bombs
    pub fn apply_pids_limit(&self, max_pids: u64) -> Result<()> {
        let pids_file = self.cgroup_path.join("pids.max");
        debug!("Writing pids.max {} to {:?}", max_pids, pids_file);
        fs::write(&pids_file, max_pids.to_string())
            .with_context(|| format!("Failed to set pids.max at {:?}", pids_file))?;
        info!("Enforced PIDs limit: max {} tasks", max_pids);
        Ok(())
    }
}

impl Drop for CgroupV2Manager {
    fn drop(&mut self) {
        if self.cgroup_path.exists() {
            debug!("Cleaning up cgroup directory {:?}", self.cgroup_path);
            let _ = fs::remove_dir(&self.cgroup_path);
        }
    }
}

/// Helper function to parse human-readable memory strings into raw bytes
pub fn parse_memory_to_bytes(input: &str) -> Result<u64> {
    let s = input.trim();
    if s.is_empty() {
        anyhow::bail!("Memory limit cannot be empty");
    }

    let (num_part, unit) = match s.chars().last() {
        Some(c) if c.is_alphabetic() => (&s[..s.len() - 1], c.to_ascii_uppercase()),
        _ => (s, 'B'),
    };

    let base: u64 = num_part
        .parse()
        .with_context(|| format!("Invalid numeric value in memory specification: '{}'", s))?;

    let bytes = match unit {
        'B' => base,
        'K' => base * 1024,
        'M' => base * 1024 * 1024,
        'G' => base * 1024 * 1024 * 1024,
        _ => anyhow::bail!("Unsupported memory unit '{}'. Use K, M, or G.", unit),
    };

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_parsing() {
        assert_eq!(parse_memory_to_bytes("1024").unwrap(), 1024);
        assert_eq!(parse_memory_to_bytes("64K").unwrap(), 64 * 1024);
        assert_eq!(parse_memory_to_bytes("128M").unwrap(), 128 * 1024 * 1024);
        assert_eq!(parse_memory_to_bytes("2G").unwrap(), 2 * 1024 * 1024 * 1024);
        assert!(parse_memory_to_bytes("invalid").is_err());
    }
}
