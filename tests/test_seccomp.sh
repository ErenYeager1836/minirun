#!/usr/bin/env bash
# ==============================================================================
# minirun Seccomp-BPF Integration Test Suite
# ==============================================================================
# Verifies synchronous syscall filtering, default denylist, clone3 ENOSYS fallback,
# clone CLONE_NEW* flag inspection, audit mode, and strict rejection.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ -z "${MINIRUN_BIN:-}" ]; then
    if [ -x "${REPO_DIR}/target/release/minirun" ] && [ "${REPO_DIR}/target/release/minirun" -nt "${REPO_DIR}/target/debug/minirun" ]; then
        MINIRUN_BIN="${REPO_DIR}/target/release/minirun"
    else
        MINIRUN_BIN="${REPO_DIR}/target/debug/minirun"
    fi
fi

if [ -z "${TESTER_BIN:-}" ]; then
    if [ -x "${REPO_DIR}/target/release/seccomp_tester" ] && [ "${REPO_DIR}/target/release/seccomp_tester" -nt "${REPO_DIR}/target/debug/seccomp_tester" ]; then
        TESTER_BIN="${REPO_DIR}/target/release/seccomp_tester"
    else
        TESTER_BIN="${REPO_DIR}/target/debug/seccomp_tester"
    fi
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

PASSED_COUNT=0
FAILED_COUNT=0

log_info() {
    echo -e "${CYAN}[INFO]${NC} $*"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
    PASSED_COUNT=$((PASSED_COUNT + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*"
    FAILED_COUNT=$((FAILED_COUNT + 1))
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $*"
}

# ------------------------------------------------------------------------------
# Pre-flight Checks
# ------------------------------------------------------------------------------
log_info "Checking environment prerequisites for minirun Seccomp..."

if [ "$(id -u)" -ne 0 ]; then
    log_skip "Seccomp integration tests require root privileges for container namespace setup."
    log_skip "To run these tests, execute: sudo ./tests/test_seccomp.sh"
    exit 0
fi

if [ ! -x "${MINIRUN_BIN}" ] || [ ! -x "${TESTER_BIN}" ]; then
    log_info "Building minirun and seccomp_tester binaries..."
    cargo build --manifest-path "${REPO_DIR}/Cargo.toml" --bin minirun --bin seccomp_tester
fi

echo "=============================================================================="
echo " Running minirun Seccomp Test Scenarios"
echo "=============================================================================="

# ------------------------------------------------------------------------------
# Test 1: Filter Installation Verification (/proc/self/status)
# ------------------------------------------------------------------------------
log_info "Test 1a: Container without --seccomp shows Seccomp: 0"
OUT_1A=$("${MINIRUN_BIN}" run -- /bin/sh -c "grep Seccomp /proc/self/status" 2>&1 || true)
if echo "${OUT_1A}" | grep -q "Seccomp:[[:space:]]*0"; then
    log_pass "Baseline container has Seccomp disabled (Seccomp: 0)."
else
    log_fail "Expected Seccomp: 0 without --seccomp flag: ${OUT_1A}"
fi

log_info "Test 1b: Container with --seccomp default shows Seccomp: 2"
OUT_1B=$("${MINIRUN_BIN}" run --seccomp default -- /bin/sh -c "grep Seccomp /proc/self/status" 2>&1 || true)
if echo "${OUT_1B}" | grep -q "Seccomp:[[:space:]]*2"; then
    log_pass "Seccomp default profile is active in kernel (Seccomp: 2)."
else
    log_fail "Expected Seccomp: 2 with --seccomp default: ${OUT_1B}"
fi

# ------------------------------------------------------------------------------
# Test 2: Control Assertions (Operations Succeed WITHOUT --seccomp)
# ------------------------------------------------------------------------------
log_info "Test 2a: Control assertion - ptrace succeeds without seccomp"
CTRL_PTRACE=$("${MINIRUN_BIN}" run -- "${TESTER_BIN}" ptrace 2>&1 || true)
if echo "${CTRL_PTRACE}" | grep -q "res=0,errno=0"; then
    log_pass "Control assertion: ptrace succeeds when seccomp is disabled."
else
    log_fail "Control assertion failed: ptrace did not succeed without seccomp: ${CTRL_PTRACE}"
fi

log_info "Test 2b: Control assertion - unshare succeeds without seccomp"
CTRL_UNSHARE=$("${MINIRUN_BIN}" run -- "${TESTER_BIN}" unshare 2>&1 || true)
if echo "${CTRL_UNSHARE}" | grep -q "res=0"; then
    log_pass "Control assertion: unshare(CLONE_NEWUSER) succeeds when seccomp is disabled."
else
    log_fail "Control assertion failed: unshare did not succeed without seccomp: ${CTRL_UNSHARE}"
fi

log_info "Test 2c: Control assertion - clone_newuser succeeds without seccomp"
CTRL_CLONE=$("${MINIRUN_BIN}" run -- "${TESTER_BIN}" clone_newuser 2>&1 || true)
if echo "${CTRL_CLONE}" | grep -E -q "res=[1-9][0-9]*,errno=0"; then
    log_pass "Control assertion: clone(CLONE_NEWUSER) succeeds when seccomp is disabled."
else
    log_fail "Control assertion failed: clone_newuser did not succeed without seccomp: ${CTRL_CLONE}"
fi

log_info "Test 2d: Control assertion - mount succeeds without seccomp"
CTRL_MOUNT=$("${MINIRUN_BIN}" run -- "${TESTER_BIN}" mount 2>&1 || true)
if echo "${CTRL_MOUNT}" | grep -q "res=0,errno=0"; then
    log_pass "Control assertion: mount succeeds when seccomp is disabled."
else
    log_fail "Control assertion failed: mount did not succeed without seccomp: ${CTRL_MOUNT}"
fi

log_info "Test 2e: Control assertion - fsopen succeeds without seccomp"
CTRL_FSOPEN=$("${MINIRUN_BIN}" run -- "${TESTER_BIN}" fsopen 2>&1 || true)
if echo "${CTRL_FSOPEN}" | grep -E -q "res=[3-9][0-9]*,errno=0|res=[1-2][0-9]+,errno=0"; then
    log_pass "Control assertion: fsopen succeeds when seccomp is disabled."
else
    log_fail "Control assertion failed: fsopen did not succeed without seccomp: ${CTRL_FSOPEN}"
fi

# Note: bpf(BPF_MAP_CREATE, NULL) returns EINVAL (errno 22) without seccomp
# because NULL attributes reach the kernel BPF subsystem; with seccomp default
# it returns EPERM (errno 1) at the syscall boundary before entering the kernel.
log_info "Test 2f: Control assertion - bpf reaches kernel handler without seccomp"
CTRL_BPF=$("${MINIRUN_BIN}" run -- "${TESTER_BIN}" bpf 2>&1 || true)
if echo "${CTRL_BPF}" | grep -q "errno=22"; then
    log_pass "Control assertion: bpf reaches kernel handler (EINVAL) without seccomp boundary rejection."
else
    log_fail "Control assertion failed: bpf did not reach kernel handler without seccomp: ${CTRL_BPF}"
fi

log_info "Test 2g: Control assertion - x32 ptrace behavior without seccomp"
CTRL_X32=$("${MINIRUN_BIN}" run -- "${TESTER_BIN}" x32_ptrace 2>&1 || true)
# Note: On kernels where x32 is disabled at boot (e.g. syscall.x32=off), the kernel returns ENOSYS (errno 38).
# With minirun's --seccomp default profile, our BPF prefix intercepts nr >= 0x40000000 and returns EPERM (errno 1),
# proving the filter enforces the sandbox boundary rather than relying on ambient kernel boot configuration.
if echo "${CTRL_X32}" | grep -q "errno=38"; then
    log_pass "Control assertion: x32 ptrace without seccomp returns kernel default ENOSYS (syscall.x32=off)."
elif echo "${CTRL_X32}" | grep -q "res=0,errno=0"; then
    log_pass "Control assertion: x32 ptrace without seccomp executes successfully (syscall.x32=y active)."
else
    log_fail "Control assertion failed: unexpected x32 behavior without seccomp: ${CTRL_X32}"
fi

# ------------------------------------------------------------------------------
# Test 3: Blocked Syscalls return EPERM under --seccomp default
# ------------------------------------------------------------------------------
log_info "Test 3a: ptrace returns EPERM (errno 1)"
OUT_PTRACE=$("${MINIRUN_BIN}" run --seccomp default -- "${TESTER_BIN}" ptrace 2>&1 || true)
if echo "${OUT_PTRACE}" | grep -q "res=-1,errno=1"; then
    log_pass "ptrace returned EPERM as expected."
else
    log_fail "ptrace was not denied with EPERM: ${OUT_PTRACE}"
fi

log_info "Test 3b: unshare(CLONE_NEWUSER) returns EPERM (errno 1)"
OUT_UNSHARE=$("${MINIRUN_BIN}" run --seccomp default -- "${TESTER_BIN}" unshare 2>&1 || true)
if echo "${OUT_UNSHARE}" | grep -q "res=-1,errno=1"; then
    log_pass "unshare(CLONE_NEWUSER) returned EPERM as expected."
else
    log_fail "unshare was not denied with EPERM: ${OUT_UNSHARE}"
fi

log_info "Test 3c: clone(CLONE_NEWUSER) returns EPERM (errno 1)"
OUT_CLONE=$("${MINIRUN_BIN}" run --seccomp default -- "${TESTER_BIN}" clone_newuser 2>&1 || true)
if echo "${OUT_CLONE}" | grep -q "res=-1,errno=1"; then
    log_pass "clone with CLONE_NEWUSER returned EPERM as expected."
else
    log_fail "clone with CLONE_NEWUSER was not denied with EPERM: ${OUT_CLONE}"
fi

log_info "Test 3d: mount returns EPERM (errno 1)"
OUT_MOUNT=$("${MINIRUN_BIN}" run --seccomp default -- "${TESTER_BIN}" mount 2>&1 || true)
if echo "${OUT_MOUNT}" | grep -q "res=-1,errno=1"; then
    log_pass "mount returned EPERM as expected."
else
    log_fail "mount was not denied with EPERM: ${OUT_MOUNT}"
fi

log_info "Test 3e: fsopen (new mount API, syscall 430) returns EPERM (errno 1)"
OUT_FSOPEN=$("${MINIRUN_BIN}" run --seccomp default -- "${TESTER_BIN}" fsopen 2>&1 || true)
if echo "${OUT_FSOPEN}" | grep -q "res=-1,errno=1"; then
    log_pass "fsopen returned EPERM as expected."
else
    log_fail "fsopen was not denied with EPERM: ${OUT_FSOPEN}"
fi

log_info "Test 3f: bpf (syscall 321) returns EPERM (errno 1)"
OUT_BPF=$("${MINIRUN_BIN}" run --seccomp default -- "${TESTER_BIN}" bpf 2>&1 || true)
if echo "${OUT_BPF}" | grep -q "res=-1,errno=1"; then
    log_pass "bpf syscall returned EPERM as expected."
else
    log_fail "bpf syscall was not denied with EPERM: ${OUT_BPF}"
fi

log_info "Test 3g: x32 ABI syscalls return EPERM (errno 1) under --seccomp default"
OUT_X32_BLOCKED=$("${MINIRUN_BIN}" run --seccomp default -- "${TESTER_BIN}" x32_ptrace 2>&1 || true)
if echo "${OUT_X32_BLOCKED}" | grep -q "res=-1,errno=1"; then
    log_pass "x32 ABI syscall returned EPERM (errno 1), closing x32 denylist bypass via BPF prefix."
else
    log_fail "x32 ABI syscall was not rejected with EPERM by BPF prefix: ${OUT_X32_BLOCKED}"
fi

# ------------------------------------------------------------------------------
# Test 4: Non-Regression Standard Workloads under --seccomp default
# ------------------------------------------------------------------------------
log_info "Test 4a: Normal command execution (echo hello)"
OUT_ECHO=$("${MINIRUN_BIN}" run --seccomp default -- /bin/echo "hello_seccomp" 2>&1 || true)
if echo "${OUT_ECHO}" | grep -q "hello_seccomp"; then
    log_pass "Normal command execution works under seccomp default."
else
    log_fail "Normal command failed under seccomp default: ${OUT_ECHO}"
fi

log_info "Test 4b: Subshell & fork() execution"
OUT_FORK=$("${MINIRUN_BIN}" run --seccomp default -- /bin/sh -c 'sh -c "echo forked_alive"' 2>&1 || true)
if echo "${OUT_FORK}" | grep -q "forked_alive"; then
    log_pass "Subshell fork() works under seccomp default."
else
    log_fail "Subshell fork() failed under seccomp default: ${OUT_FORK}"
fi

log_info "Test 4c: Shell pipeline (echo | cat)"
OUT_PIPE=$("${MINIRUN_BIN}" run --seccomp default -- /bin/sh -c 'echo "pipe_alive" | cat' 2>&1 || true)
if echo "${OUT_PIPE}" | grep -q "pipe_alive"; then
    log_pass "Shell pipeline works under seccomp default."
else
    log_fail "Shell pipeline failed under seccomp default: ${OUT_PIPE}"
fi

log_info "Test 4d: Threading (verifies clone3 ENOSYS fallback to clone)"
OUT_THREAD=$("${MINIRUN_BIN}" run --seccomp default -- "${TESTER_BIN}" threading 2>&1 || true)
if echo "${OUT_THREAD}" | grep -q "thread_alive"; then
    log_pass "Threading succeeded via clone3 ENOSYS fallback to clone()."
else
    log_fail "Threading failed under seccomp default: ${OUT_THREAD}"
fi

# ------------------------------------------------------------------------------
# Test 5: Audit Mode (--seccomp audit allows call, observe-only)
# ------------------------------------------------------------------------------
log_info "Test 5a: Audit mode allows unshare without returning EPERM"
OUT_AUDIT=$("${MINIRUN_BIN}" run --seccomp audit -- "${TESTER_BIN}" unshare 2>&1 || true)
if echo "${OUT_AUDIT}" | grep -q "res=0"; then
    log_pass "Audit mode allowed unshare(CLONE_NEWUSER) without returning EPERM."
else
    log_fail "Audit mode blocked unshare: ${OUT_AUDIT}"
fi

log_info "Test 5b: Audit mode emits kernel audit log (SECCOMP_RET_LOG)"
if dmesg 2>/dev/null | grep -q "comm=\"seccomp_tester\".*syscall=272.*code=0x7ffc0000"; then
    log_pass "Audit record (syscall=272, code=0x7ffc0000) verified in dmesg."
else
    log_skip "dmesg audit log check skipped (dmesg restricted or auditd forwarding enabled)."
fi

log_info "Test 5c: Audit mode remains observe-only for x32 syscalls"
OUT_AUDIT_X32=$("${MINIRUN_BIN}" run --seccomp audit -- "${TESTER_BIN}" x32_ptrace 2>&1 || true)
if echo "${OUT_AUDIT_X32}" | grep -q "errno=38"; then
    log_pass "Audit mode allowed x32 syscall to pass to kernel without returning EPERM (observe-only)."
else
    log_fail "Audit mode unexpectedly altered x32 syscall behavior: ${OUT_AUDIT_X32}"
fi

# ------------------------------------------------------------------------------
# Test 6: Strict Mode Rejection (--seccomp strict)
# ------------------------------------------------------------------------------
log_info "Test 6: Strict mode returns 'not yet implemented' error"
set +e
OUT_STRICT=$("${MINIRUN_BIN}" run --seccomp strict -- /bin/echo "strict_test" 2>&1)
EXIT_STRICT=$?
set -e

if [ "${EXIT_STRICT}" -ne 0 ] && echo "${OUT_STRICT}" | grep -iq "not yet implemented"; then
    log_pass "Strict mode rejected with clear 'not yet implemented' error (exit: ${EXIT_STRICT})."
else
    log_fail "Strict mode did not reject as expected: ${OUT_STRICT}"
fi

# ------------------------------------------------------------------------------
# Test 7: Rootless Mode with Seccomp (--rootless --seccomp default)
# ------------------------------------------------------------------------------
log_info "Test 7: Rootless mode with --seccomp default installs filter"
OUT_ROOTLESS=$("${MINIRUN_BIN}" run --rootless --seccomp default -- /bin/sh -c "grep Seccomp /proc/self/status" 2>&1 || true)
if echo "${OUT_ROOTLESS}" | grep -q "Seccomp:[[:space:]]*2"; then
    log_pass "Rootless container installed Seccomp filter successfully (Seccomp: 2)."
else
    log_fail "Rootless container failed to install Seccomp filter: ${OUT_ROOTLESS}"
fi

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo "=============================================================================="
echo -e "Results: ${GREEN}${PASSED_COUNT} Passed${NC}, ${RED}${FAILED_COUNT} Failed${NC}"
echo "=============================================================================="

if [ "${FAILED_COUNT}" -gt 0 ]; then
    exit 1
fi
exit 0
