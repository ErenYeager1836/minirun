#!/usr/bin/env bash
# ==============================================================================
# minirun Interactive Terminal Demo Script
# ==============================================================================
# Pre-requisite: Run 'sudo -v' before recording to cache sudo credentials
# so password prompts do not appear on camera.
#
# Suitable for recording with asciinema or VHS:
#   sudo -v && asciinema rec demo.cast -c ./scripts/demo.sh
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Run from repository root with a clean prompt
cd "${REPO_DIR}"
export PS1="minirun$ "

MINIRUN="./target/release/minirun"
if [ ! -f "${MINIRUN}" ]; then
    MINIRUN="./target/debug/minirun"
fi

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

step() {
    echo -e "\n${BOLD}${CYAN}==> $1${NC}"
    sleep 1.2
}

clear
echo -e "${BOLD}minirun - Linux Container Runtime & eBPF Active Defense${NC}"
echo -e "Demonstration: Namespaces, Cgroups v2, Seccomp-BPF & Guard\n"
sleep 1

# 1. System Doctor
step "1. Checking host kernel prerequisites with 'minirun doctor'..."
"${MINIRUN}" doctor
sleep 2

# 2. Seccomp Syscall Sandboxing
step "2. Seccomp-BPF Syscall Sandboxing (--seccomp default)..."
echo "Attempting to create a user namespace inside container (unshare)..."
sudo "${MINIRUN}" run --seccomp default -- sh -c 'unshare -U 2>&1 || echo "Blocked by Seccomp (EPERM)"'
sleep 2

# 3. Guard Telemetry (Audit Mode)
step "3. Guard Telemetry in Audit Mode (--guard audit)..."
echo "Simulating credential access: cat /etc/shadow..."
sudo "${MINIRUN}" run --guard audit -- sh -c 'cat /etc/shadow 2>/dev/null || true'
sleep 2

# 4. Guard Active Enforcement (Enforce Mode)
step "4. Guard Active Enforcement (--guard enforce)..."
echo "Simulating reverse shell sequence: connect -> dup2 -> exec(/bin/sh)..."
sudo "${MINIRUN}" run --guard enforce -- /bin/sh -c 'python3 -c "import socket, threading, time, os; t=threading.Thread(target=lambda: (lambda s: (s.bind((\"127.0.0.1\", 19876)), s.listen(1), s.accept()))(socket.socket(socket.AF_INET, socket.SOCK_STREAM))); t.daemon=True; t.start(); time.sleep(0.15); s=socket.socket(); s.connect((\"127.0.0.1\", 19876)); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.system(\"/bin/sh -c exit\")"' || echo -e "${RED}[ENFORCED] Container terminated with exit status 137 (SIGKILL)${NC}"

echo -e "\n${BOLD}${GREEN}Demo Complete!${NC}\n"
