#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-}"
NIC="${2:-}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

XDP_OBJ="${REPO_ROOT}/internal/forwarder/xdpsmoke_bpfel.o"
XDP_SEC="xdp"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/ebpf_nic.sh up <nic>       # Attach XDP
  ./scripts/ebpf_nic.sh down <nic>     # Detach XDP
  ./scripts/ebpf_nic.sh status <nic>   # Show attach status
  ./scripts/ebpf_nic.sh gen            # Generate bpf2go artifacts
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing command: $1"
    exit 1
  }
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Please run with sudo/root."
    exit 1
  fi
}

check_nic() {
  ip link show dev "${NIC}" >/dev/null 2>&1 || {
    echo "NIC not found: ${NIC}"
    exit 1
  }
}

generate() {
  need_cmd go
  (cd "${REPO_ROOT}" && go generate ./internal/forwarder)
  echo "Generated eBPF artifacts."
}

attach() {
  need_root
  need_cmd ip
  check_nic

  [[ -f "${XDP_OBJ}" ]] || { echo "Missing ${XDP_OBJ}. Run: $0 gen"; exit 1; }

  ip link set dev "${NIC}" xdp off 2>/dev/null || true
  ip link set dev "${NIC}" xdp obj "${XDP_OBJ}" sec "${XDP_SEC}"

  echo "Attached XDP to ${NIC}"
}

detach() {
  need_root
  need_cmd ip
  check_nic

  ip link set dev "${NIC}" xdp off 2>/dev/null || true

  echo "Detached XDP from ${NIC}"
}

status() {
  need_cmd ip
  check_nic

  echo "=== XDP (${NIC}) ==="
  ip -details link show dev "${NIC}" | sed -n '/xdp/q;p' || true
  ip -details link show dev "${NIC}" | rg -n "xdp|prog/xdp" || true
}

case "${ACTION}" in
  gen)
    generate
    ;;
  up)
    [[ -n "${NIC}" ]] || { usage; exit 1; }
    attach
    ;;
  down)
    [[ -n "${NIC}" ]] || { usage; exit 1; }
    detach
    ;;
  status)
    [[ -n "${NIC}" ]] || { usage; exit 1; }
    status
    ;;
  *)
    usage
    exit 1
    ;;
esac