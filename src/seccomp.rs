// src/seccomp.rs
// ==============================================================================
// minirun Seccomp-BPF Syscall Filter Manager
// ==============================================================================
// Implements synchronous kernel syscall filtering via seccomp(SECCOMP_SET_MODE_FILTER).
// Complements eBPF Guard's asynchronous runtime telemetry with static syscall rejection.
// ==============================================================================

use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SeccompMode {
    /// Denylist dangerous syscalls with EPERM (default container profile)
    Default,
    /// Allowlist standard container POSIX syscalls (Not yet implemented)
    Strict,
    /// Run default denylist in observe-only audit mode via SECCOMP_RET_LOG
    Audit,
    /// Disable seccomp filtering
    None,
}

#[cfg(target_arch = "x86_64")]
mod backend {
    use super::*;
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };
    use std::collections::BTreeMap;

    // Fallback definitions for modern Linux syscall numbers on x86_64
    // Ensures build reliability even if compiled with older libc crates
    const SYS_OPEN_TREE: i64 = 428;
    const SYS_MOVE_MOUNT: i64 = 429;
    const SYS_FSOPEN: i64 = 430;
    const SYS_FSCONFIG: i64 = 431;
    const SYS_FSMOUNT: i64 = 432;
    const SYS_FSPICK: i64 = 433;
    const SYS_MOUNT_SETATTR: i64 = 442;

    pub struct SeccompManager;

    impl SeccompManager {
        /// Compiles the BPF filters based on the selected mode.
        /// Returns an optional tuple of (clone3_filter, denylist_filter).
        pub fn build_filters(mode: SeccompMode) -> Result<Option<(Option<BpfProgram>, BpfProgram)>> {
            match mode {
                SeccompMode::None => Ok(None),
                SeccompMode::Strict => {
                    bail!("Seccomp strict mode (allowlist) is not yet implemented. Use '--seccomp default' or '--seccomp audit'.");
                }
                SeccompMode::Default | SeccompMode::Audit => {
                    let is_audit = mode == SeccompMode::Audit;

                    // Reject action: In Default mode, denied syscalls return EPERM.
                    // In Audit mode, violations are logged to kernel audit log/dmesg via SECCOMP_RET_LOG.
                    let reject_action = if is_audit {
                        SeccompAction::Log
                    } else {
                        SeccompAction::Errno(libc::EPERM as u32)
                    };

                    // -------------------------------------------------------------
                    // 1. clone3 Filter: Returns ENOSYS so libc falls back to clone()
                    // -------------------------------------------------------------
                    // NOTE: In Audit mode, we DO NOT install the clone3 ENOSYS filter,
                    // ensuring audit mode remains strictly observe-only without altering
                    // application threading or process spawning behavior.
                    let clone3_prog = if !is_audit {
                        let clone3_filter = SeccompFilter::new(
                            [(libc::SYS_clone3, vec![])].into_iter().collect(),
                            SeccompAction::Allow,
                            SeccompAction::Errno(libc::ENOSYS as u32),
                            TargetArch::x86_64,
                        )
                        .context("Failed to construct clone3 seccomp filter")?;

                        Some(
                            clone3_filter
                                .try_into()
                                .context("Failed to compile clone3 filter to BPF")?,
                        )
                    } else {
                        None
                    };

                    // -------------------------------------------------------------
                    // 2. Denylist Filter: Dangerous syscalls return EPERM (or Log)
                    // -------------------------------------------------------------
                    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

                    // Unconditional denylist (empty rule vector matches any arguments)
                    let denied_syscalls: &[i64] = &[
                        // Process tracing, kernel module tampering & hardware reboot
                        libc::SYS_ptrace,
                        libc::SYS_kexec_load,
                        libc::SYS_kexec_file_load,
                        libc::SYS_reboot,
                        libc::SYS_init_module,
                        libc::SYS_finit_module,
                        libc::SYS_delete_module,
                        libc::SYS_bpf,
                        // Classic & modern mount APIs (prevents unprivileged remounts & filesystem hijacking)
                        libc::SYS_mount,
                        libc::SYS_umount2,
                        libc::SYS_pivot_root,
                        libc::SYS_unshare,
                        libc::SYS_setns,
                        SYS_FSOPEN,
                        SYS_FSCONFIG,
                        SYS_FSMOUNT,
                        SYS_FSPICK,
                        SYS_MOVE_MOUNT,
                        SYS_OPEN_TREE,
                        SYS_MOUNT_SETATTR,
                        // Classic container breakout primitives & handle traversal
                        libc::SYS_open_by_handle_at,
                        libc::SYS_name_to_handle_at,
                        libc::SYS_lookup_dcookie,
                        // Kernel keyrings, tracing, cross-process memory inspection
                        libc::SYS_keyctl,
                        libc::SYS_add_key,
                        libc::SYS_request_key,
                        libc::SYS_perf_event_open,
                        libc::SYS_process_vm_readv,
                        libc::SYS_process_vm_writev,
                        libc::SYS_userfaultfd,
                        // Hardware I/O, swap, system clock adjustment & accounting
                        libc::SYS_swapon,
                        libc::SYS_swapoff,
                        libc::SYS_settimeofday,
                        libc::SYS_adjtimex,
                        libc::SYS_clock_adjtime,
                        libc::SYS_clock_settime,
                        libc::SYS_acct,
                        libc::SYS_quotactl,
                        libc::SYS_iopl,
                        libc::SYS_ioperm,
                    ];

                    for &nr in denied_syscalls {
                        rules.insert(nr, vec![]);
                    }

                    // Conditional clone inspection: Block if any CLONE_NEW* flag is passed
                    // Argument 0 on x86_64 clone is `flags`.
                    let clone_new_flags = [
                        libc::CLONE_NEWUSER as u64,
                        libc::CLONE_NEWNS as u64,
                        libc::CLONE_NEWPID as u64,
                        libc::CLONE_NEWNET as u64,
                        libc::CLONE_NEWIPC as u64,
                        libc::CLONE_NEWUTS as u64,
                        libc::CLONE_NEWCGROUP as u64,
                    ];

                    let mut clone_rules = Vec::new();
                    for flag in clone_new_flags {
                        clone_rules.push(SeccompRule::new(vec![SeccompCondition::new(
                            0, // arg0 is flags on x86_64
                            SeccompCmpArgLen::Dword,
                            SeccompCmpOp::MaskedEq(flag),
                            flag,
                        )?])?);
                    }
                    rules.insert(libc::SYS_clone, clone_rules);

                    let denylist_filter = SeccompFilter::new(
                        rules,
                        SeccompAction::Allow,
                        reject_action,
                        TargetArch::x86_64,
                    )
                    .context("Failed to construct denylist seccomp filter")?;

                    let denylist_prog: BpfProgram = denylist_filter
                        .try_into()
                        .context("Failed to compile denylist filter to BPF")?;

                    Ok(Some((clone3_prog, denylist_prog)))
                }
            }
        }

        /// Installs the Seccomp filters immediately before execvp().
        ///
        /// # Arguments
        /// * `mode` - The requested seccomp profile.
        /// * `set_no_new_privs` - Whether to invoke prctl(PR_SET_NO_NEW_PRIVS). Mandatory
        ///   for rootless/non-root containers; omitted for root containers to keep setuid binaries functional.
        pub fn apply(mode: SeccompMode, set_no_new_privs: bool) -> Result<()> {
            let progs = match Self::build_filters(mode)? {
                Some(p) => p,
                None => return Ok(()),
            };

            let (clone3_prog, denylist_prog) = progs;

            // 1. Set PR_SET_NO_NEW_PRIVS if requested or running rootless/unprivileged
            if set_no_new_privs {
                if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("Failed to set PR_SET_NO_NEW_PRIVS before seccomp load");
                }
                info!("Enforced PR_SET_NO_NEW_PRIVS");
            }

            // 2. Apply filters: clone3 fallback (if default mode) then denylist
            if let Some(c3_prog) = clone3_prog {
                seccompiler::apply_filter(&c3_prog)
                    .context("Failed to apply clone3 ENOSYS seccomp filter")?;
            }

            seccompiler::apply_filter(&denylist_prog)
                .context("Failed to apply denylist seccomp filter")?;

            info!("Installed Seccomp profile '{:?}' successfully", mode);
            Ok(())
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod backend {
    use super::*;

    pub struct SeccompManager;

    impl SeccompManager {
        pub fn apply(_mode: SeccompMode, _set_no_new_privs: bool) -> Result<()> {
            bail!("Seccomp-BPF filters in minirun currently support x86_64 architecture only");
        }
    }
}

pub use backend::SeccompManager;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_none() {
        let res = SeccompManager::build_filters(SeccompMode::None).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn test_seccomp_strict_not_implemented() {
        let res = SeccompManager::build_filters(SeccompMode::Strict);
        assert!(res.is_err());
        let err_msg = format!("{:?}", res.err().unwrap());
        assert!(err_msg.contains("not yet implemented"));
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_seccomp_default_builds() {
        let res = SeccompManager::build_filters(SeccompMode::Default).unwrap();
        assert!(res.is_some());
        let (clone3_prog, denylist_prog) = res.unwrap();
        assert!(clone3_prog.is_some());
        assert!(!denylist_prog.is_empty());
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_seccomp_audit_builds_without_clone3() {
        let res = SeccompManager::build_filters(SeccompMode::Audit).unwrap();
        assert!(res.is_some());
        let (clone3_prog, denylist_prog) = res.unwrap();
        // In Audit mode, clone3 ENOSYS filter must be omitted to ensure observe-only behavior
        assert!(clone3_prog.is_none());
        assert!(!denylist_prog.is_empty());
    }
}
