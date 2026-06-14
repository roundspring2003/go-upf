#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${REPO_ROOT}/e2e/run"
LOG_DIR="${REPO_ROOT}/e2e/logs/$(date +%Y%m%d-%H%M%S)"
UPF_BIN="${REPO_ROOT}/bin/upf"
UPF_CONFIG="${UPF_CONFIG:-${REPO_ROOT}/config/upfcfg.yaml}"
NIC="${E2E_NIC:-enx000ec687a702}"
UPF_IP="${E2E_UPF_IP:-192.168.113.21}"
SMF_IP="${E2E_SMF_IP:-192.168.113.20}"
XDP_ENABLED="${E2E_XDP:-1}"
UPF_CPUS="${UPF_CPUS:-16-19}"
XDP_MARKER="${RUN_DIR}/xdp.nic"

mkdir -p "${RUN_DIR}" "${LOG_DIR}"

case "${XDP_ENABLED}" in
  0|1) ;;
  *)
    printf 'E2E_XDP must be 0 or 1; got %s.\n' "${XDP_ENABLED}" >&2
    exit 1
    ;;
esac

if [[ ! -x "${UPF_BIN}" ]]; then
  printf 'UPF binary not found: %s\n' "${UPF_BIN}" >&2
  printf 'Build it first with: go build -o bin/upf ./cmd/main.go\n' >&2
  exit 1
fi
if [[ ! -r "/sys/class/net/${NIC}/carrier" ]]; then
  printf 'NIC not found: %s\n' "${NIC}" >&2
  exit 1
fi
if [[ "$(cat "/sys/class/net/${NIC}/carrier")" != "1" ]]; then
  printf 'No carrier on %s. Check the direct cable.\n' "${NIC}" >&2
  exit 1
fi
if ! ip -4 -o addr show dev "${NIC}" | awk '{print $4}' | grep -q "^${UPF_IP}/"; then
  printf '%s does not have expected UPF IP %s.\n' "${NIC}" "${UPF_IP}" >&2
  ip -br addr show dev "${NIC}" >&2
  exit 1
fi
if ! ping -c 1 -W 1 "${SMF_IP}" >/dev/null; then
  printf 'SMF host %s is not reachable over %s.\n' "${SMF_IP}" "${NIC}" >&2
  exit 1
fi
if ! lsmod | awk '{print $1}' | grep -qx gtp5g; then
  printf 'gtp5g is not loaded. Install/load it before starting XT-UPF.\n' >&2
  exit 1
fi

sudo -v
"${REPO_ROOT}/scripts/e2e_upf_stop.sh"

# XT-UPF normally requires gtp5g < 0.10.0. This experiment intentionally uses
# the currently loaded module (0.10.2 on this host) without reinstalling it.
export GO_UPF_ALLOW_UNSUPPORTED_GTP5G=1

cleanup_failed_start() {
  rm -f "${RUN_DIR}/upf.pid"
  if [[ -f "${XDP_MARKER}" ]]; then
    sudo "${REPO_ROOT}/scripts/ebpf_nic.sh" down "$(cat "${XDP_MARKER}")" || true
    rm -f "${XDP_MARKER}"
  fi
}
trap cleanup_failed_start ERR

if [[ "${XDP_ENABLED}" == "1" ]]; then
  unset GO_UPF_DISABLE_XDP_QOS
  sudo "${REPO_ROOT}/scripts/ebpf_nic.sh" up "${NIC}"
  printf '%s\n' "${NIC}" >"${XDP_MARKER}"
else
  export GO_UPF_DISABLE_XDP_QOS=1
  sudo "${REPO_ROOT}/scripts/ebpf_nic.sh" down "${NIC}"
  rm -f "${XDP_MARKER}"
fi

sudo -E nohup taskset -c "${UPF_CPUS}" "${UPF_BIN}" -c "${UPF_CONFIG}" \
  -l "${LOG_DIR}/upf.log" >"${LOG_DIR}/upf.stdout.log" 2>&1 &
sleep 2
pid="$(pgrep -n -f "^${UPF_BIN} -c ${UPF_CONFIG}( |$)" || true)"
if [[ -z "${pid}" ]] || ! sudo kill -0 "${pid}" 2>/dev/null; then
  printf 'XT-UPF exited during startup.\n' >&2
  tail -n 50 "${LOG_DIR}/upf.stdout.log" >&2 || true
  exit 1
fi
printf '%s\n' "${pid}" >"${RUN_DIR}/upf.pid"

trap - ERR

printf 'XT-UPF started (pid %s, CPUs=%s, XDP=%s, N3=%s). Logs: %s\n' \
  "${pid}" "${UPF_CPUS}" "${XDP_ENABLED}" "${NIC}" "${LOG_DIR}"
taskset -pc "${pid}"
ss -lupn | grep -E '192\.168\.113\.21:(8805|2152)\b' || true
