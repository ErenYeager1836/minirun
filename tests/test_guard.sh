#!/usr/bin/env bash
# ==============================================================================
# minirun Guard Integration Test Suite
# ==============================================================================
# Verifies eBPF runtime security telemetry, cgroup scoping, event correlation,
# reverse-shell sequence detection, sensitive path filtering, and enforce mode.
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
log_info "Checking environment prerequisites for minirun Guard..."

if [ "$(id -u)" -ne 0 ]; then
    log_skip "Guard integration tests require root privileges (CAP_BPF, CAP_PERFMON, and cgroup v2 controller access)."
    log_skip "To run these tests, execute: sudo ./tests/test_guard.sh"
    exit 0
fi

if [ ! -f "/sys/kernel/btf/vmlinux" ]; then
    log_skip "Kernel BTF (/sys/kernel/btf/vmlinux) is not available on this system."
    exit 0
fi

if [ ! -f "/sys/fs/cgroup/cgroup.controllers" ]; then
    log_skip "Cgroups v2 unified hierarchy (/sys/fs/cgroup/cgroup.controllers) is not available."
    exit 0
fi

if [ ! -x "${MINIRUN_BIN}" ]; then
    log_info "Building minirun binary..."
    cargo build --manifest-path "${REPO_DIR}/Cargo.toml"
fi

TEST_PORT=19876

# Ensure background jobs cleanup on exit
cleanup() {
    jobs -p | xargs -r kill 2>/dev/null || true
}
trap cleanup EXIT

echo "=============================================================================="
echo " Running minirun Guard Test Scenarios"
echo "=============================================================================="

# ------------------------------------------------------------------------------
# Test 1: Benign Command (No Alerts)
# ------------------------------------------------------------------------------
log_info "Test 1: Benign Command (/bin/echo hello) with --guard audit"
OUT_1=$("${MINIRUN_BIN}" run --guard audit -- /bin/echo "hello" 2>&1 || true)

if echo "${OUT_1}" | grep -q "hello" && ! echo "${OUT_1}" | grep -q "\[GUARD ALERT\]"; then
    log_pass "Benign command exited 0 with zero security alerts."
else
    log_fail "Benign command output unexpected alert or failed: ${OUT_1}"
fi

# ------------------------------------------------------------------------------
# Test 2: Recon / Exec Detection & Host PID Semantics
# ------------------------------------------------------------------------------
log_info "Test 2: Recon / Exec Detection (whoami / nc)"
OUT_2=$("${MINIRUN_BIN}" run --guard audit -- /bin/sh -c "whoami" 2>&1 || true)

if echo "${OUT_2}" | grep -q "\[GUARD ALERT\]" && echo "${OUT_2}" | grep -q "whoami"; then
    log_pass "Detected subsequent exec of recon command with host PID semantics."
else
    log_fail "Failed to detect whoami exec: ${OUT_2}"
fi

# ------------------------------------------------------------------------------
# Test 3: Egress Outbound Network Connection
# Note: In private network namespace (CLONE_NEWNET), lo must be configured UP
# to allow loopback sockets to perform connect().
# ------------------------------------------------------------------------------
log_info "Test 3: Egress Outbound Socket Connection"
OUT_3=$("${MINIRUN_BIN}" run --guard audit -- /bin/sh -c "ip link set lo up 2>/dev/null || ifconfig lo up 2>/dev/null || true; python3 -c 'import socket; s = socket.socket(); s.connect_ex((\"127.0.0.1\", ${TEST_PORT}))' 2>/dev/null || true" 2>&1 || true)

if echo "${OUT_3}" | grep -q "\[GUARD ALERT\]" && echo "${OUT_3}" | grep -q "${TEST_PORT}"; then
    log_pass "Captured sys_enter_connect telemetry to 127.0.0.1:${TEST_PORT}."
else
    log_fail "Failed to capture connect telemetry to 127.0.0.1:${TEST_PORT}: ${OUT_3}"
fi

# ------------------------------------------------------------------------------
# Test 4: Reverse Shell Sequence Correlation (connect -> dup2 -> exec shell)
# Note: Listener must run inside the container's network namespace so loopback
# connection succeeds and reaches dup2 redirection.
# ------------------------------------------------------------------------------
log_info "Test 4: Reverse Shell Sequence Correlation"
REVERSE_SHELL_CMD=""
if command -v python3 >/dev/null 2>&1; then
    # In-container Python loopback listener + connect + dup2 + exec shell
    REVERSE_SHELL_CMD="python3 -c 'import socket, threading, time, os; t=threading.Thread(target=lambda: (lambda s: (s.bind((\"127.0.0.1\", ${TEST_PORT})), s.listen(1), s.accept()))(socket.socket(socket.AF_INET, socket.SOCK_STREAM))); t.daemon=True; t.start(); time.sleep(0.15); s=socket.socket(); s.connect((\"127.0.0.1\", ${TEST_PORT})); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.system(\"/bin/sh -c exit\")'"
elif command -v nc >/dev/null 2>&1 && command -v bash >/dev/null 2>&1; then
    # In-container netcat listener + bash TCP redirection
    REVERSE_SHELL_CMD="nc -l -p ${TEST_PORT} >/dev/null 2>&1 & sleep 0.2; bash -i >& /dev/tcp/127.0.0.1/${TEST_PORT} 0>&1"
fi

if [ -z "${REVERSE_SHELL_CMD}" ]; then
    log_skip "Test 4: Skipped (requires python3 or nc+bash in test environment for in-container listener)."
else
    OUT_4=$("${MINIRUN_BIN}" run --guard audit -- /bin/sh -c "${REVERSE_SHELL_CMD}" 2>&1 || true)
    if echo "${OUT_4}" | grep -q "\[CRITICAL\]" && echo "${OUT_4}" | grep -iq "reverse shell"; then
        log_pass "Correlated full reverse-shell sequence (connect -> dup2 -> exec) as CRITICAL."
    else
        log_fail "Reverse shell sequence was not detected: ${OUT_4}"
    fi
fi

# ------------------------------------------------------------------------------
# Test 5: Sensitive Path Access vs Normal File Access (open/openat/openat2)
# ------------------------------------------------------------------------------
log_info "Test 5a: Sensitive Path Access (/etc/shadow)"
OUT_5A=$("${MINIRUN_BIN}" run --guard audit -- /bin/cat /etc/shadow 2>&1 || true)

if echo "${OUT_5A}" | grep -q "\[GUARD ALERT\]" && echo "${OUT_5A}" | grep -q "/etc/shadow"; then
    log_pass "Captured sensitive file access alert for /etc/shadow."
else
    log_fail "Failed to capture /etc/shadow access alert: ${OUT_5A}"
fi

log_info "Test 5b: Normal File Access (/etc/hosts) should produce NO alerts"
OUT_5B=$("${MINIRUN_BIN}" run --guard audit -- /bin/cat /etc/hosts 2>&1 || true)

if ! echo "${OUT_5B}" | grep -q "\[GUARD ALERT\]"; then
    log_pass "Normal file open produced zero security alerts."
else
    log_fail "Normal file open triggered false alert: ${OUT_5B}"
fi

# ------------------------------------------------------------------------------
# Test 6: Enforce Mode - Initial Exec Exemption & Subshell Survival
# ------------------------------------------------------------------------------
log_info "Test 6a: Enforce Mode - Initial Shell Entrypoint Exemption"
OUT_6A=$("${MINIRUN_BIN}" run --guard enforce -- /bin/sh -c 'echo "entrypoint_alive"' 2>&1 || true)

if echo "${OUT_6A}" | grep -q "entrypoint_alive"; then
    log_pass "Container launched with /bin/sh entrypoint survived under --guard enforce (init_exec_seen exemption verified)."
else
    log_fail "Container killed on initial shell entrypoint under enforce mode: ${OUT_6A}"
fi

log_info "Test 6b: Enforce Mode - Non-critical Shell Exec (Survives, HIGH Alert Only)"
OUT_6B=$("${MINIRUN_BIN}" run --guard enforce -- /bin/sh -c 'sh -c "echo subshell_survived"' 2>&1 || true)

if echo "${OUT_6B}" | grep -q "subshell_survived" && echo "${OUT_6B}" | grep -q "\[HIGH\]"; then
    log_pass "Subshell execution produced HIGH alert without triggering enforce termination."
else
    log_fail "Subshell execution either failed or triggered unwarranted enforcement: ${OUT_6B}"
fi

log_info "Test 6c: Enforce Mode - CRITICAL Reverse Shell Termination"
if [ -z "${REVERSE_SHELL_CMD}" ]; then
    log_skip "Test 6c: Skipped (requires python3 or nc+bash in test environment for in-container listener)."
else
    set +e
    OUT_6C=$("${MINIRUN_BIN}" run --guard enforce -- /bin/sh -c "${REVERSE_SHELL_CMD}" 2>&1)
    EXIT_6C=$?
    set -e

    if [ "${EXIT_6C}" -eq 137 ] || echo "${OUT_6C}" | grep -q "\[ENFORCED: KILLED\]"; then
        log_pass "Enforce mode successfully terminated the container on CRITICAL reverse shell (exit: ${EXIT_6C})."
    else
        log_fail "Enforce mode did not kill container on reverse shell (exit: ${EXIT_6C}): ${OUT_6C}"
    fi
fi

# ------------------------------------------------------------------------------
# Test 7: Host Isolation & Scoping (Noisy Host Produces Zero Container Alerts)
# ------------------------------------------------------------------------------
log_info "Test 7: Host Isolation Scoping"
# Run noisy host actions in background
(for i in {1..5}; do cat /etc/shadow >/dev/null 2>&1 || true; whoami >/dev/null 2>&1 || true; sleep 0.05; done) &
NOISE_PID=$!

OUT_7=$("${MINIRUN_BIN}" run --guard audit -- /bin/echo "isolated" 2>&1 || true)
wait "${NOISE_PID}" 2>/dev/null || true

if echo "${OUT_7}" | grep -q "isolated" && ! echo "${OUT_7}" | grep -q "\[GUARD ALERT\]"; then
    log_pass "Host-side activity did not leak any events into the container Guard filter."
else
    log_fail "Host activity leaked into container Guard monitor: ${OUT_7}"
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
