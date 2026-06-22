#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
NIC="${E2E_NIC:-enx000ec687a702}"
UPF_IP="${E2E_UPF_IP:-192.168.113.21}"
GNB_IP="${GNB_IP:-192.168.113.20}"
UPF_CPUS="${UPF_CPUS:-16-19}"
TARGET_PPS="${TARGET_PPS:-10000}"
DURATION="${EXPERIMENT_DURATION:-30}"
GRACE="${RECEIVE_GRACE:-2}"
QOS_FLOWS="${MOCK_QOS_FLOWS:-7:1,8:2,9:3}"
PRESSURE="${CPU_PRESSURE:-0}"
RESULT_ROOT="${PHYSICAL_RESULT_ROOT:-${REPO_ROOT}/experiments}"
RESULT_DIR="${RESULT_ROOT}/physical-performance-${MODE}-$(date +%Y%m%d-%H%M%S)"
UPFTEST="${REPO_ROOT}/bin/upftest"
XDPSTATS="${REPO_ROOT}/bin/xdpstats"
GTPUPROBE="${REPO_ROOT}/bin/gtpuprobe"
RPS_FILE="/sys/class/net/${NIC}/queues/rx-0/rps_cpus"
ECHO_PID=""
ORIGINAL_RPS=""
PRESSURE_PIDS=()

usage() {
  echo "Usage: $0 {native|xdp-steering}" >&2
}

case "${MODE}" in
  native) XDP_ENABLED=0 ;;
  xdp-steering) XDP_ENABLED=1 ;;
  *) usage; exit 2 ;;
esac

if [[ "${EUID}" -eq 0 ]]; then
  echo "Run as the normal user; the script invokes sudo where required." >&2
  exit 1
fi
if [[ ! -f "${RPS_FILE}" ]]; then
  echo "Missing RX queue RPS file: ${RPS_FILE}" >&2
  exit 1
fi
if [[ "$(find "/sys/class/net/${NIC}/queues" -maxdepth 1 -type d -name 'rx-*' | wc -l)" -ne 1 ]]; then
  echo "This experiment expects exactly one RX queue on ${NIC}." >&2
  exit 1
fi

mkdir -p "${REPO_ROOT}/bin" "${RESULT_DIR}"
(cd "${REPO_ROOT}" && go build -o bin/upf ./cmd/main.go)
(cd "${REPO_ROOT}" && go build -o bin/upftest ./testtools/upftest)
(cd "${REPO_ROOT}" && go build -o bin/xdpstats ./testtools/xdpstats)
(cd "${REPO_ROOT}" && go build -o bin/gtpuprobe ./testtools/gtpuprobe)
sudo -v
ORIGINAL_RPS="$(cat "${RPS_FILE}")"

stop_pressure() {
  if (( ${#PRESSURE_PIDS[@]} > 0 )); then
    kill "${PRESSURE_PIDS[@]}" 2>/dev/null || true
    wait "${PRESSURE_PIDS[@]}" 2>/dev/null || true
  fi
  PRESSURE_PIDS=()
}

cleanup() {
  stop_pressure
  if [[ -n "${ECHO_PID}" ]]; then
    kill "${ECHO_PID}" 2>/dev/null || true
    wait "${ECHO_PID}" 2>/dev/null || true
  fi
  "${REPO_ROOT}/scripts/e2e_upf_stop.sh" || true
  if [[ -n "${ORIGINAL_RPS}" && -f "${RPS_FILE}" ]]; then
    printf '%s\n' "${ORIGINAL_RPS}" | sudo tee "${RPS_FILE}" >/dev/null || true
  fi
}
trap cleanup EXIT

printf '0\n' | sudo tee "${RPS_FILE}" >/dev/null

E2E_XDP="${XDP_ENABLED}" E2E_NIC="${NIC}" E2E_UPF_IP="${UPF_IP}" \
  E2E_SMF_IP="${GNB_IP}" UPF_CPUS="${UPF_CPUS}" \
  "${REPO_ROOT}/scripts/e2e_upf_start.sh"

"${UPFTEST}" \
  -s "${UPF_IP}:8805" \
  -n "${GNB_IP}" \
  -ue-ip 10.60.0.1 \
  -access-teid 1 \
  -access-ip "${GNB_IP}" \
  -dl-teid 2 \
  -dl-peer-ip "${GNB_IP}" \
  -qos-flows "${QOS_FLOWS}" >"${RESULT_DIR}/mock-smf.log" 2>&1

taskset -c 0-15 "${GTPUPROBE}" echo --listen "${UPF_IP}:9000" >"${RESULT_DIR}/echo.log" 2>&1 &
ECHO_PID=$!
sleep 1
if ! kill -0 "${ECHO_PID}" 2>/dev/null; then
  echo "UDP echo server failed to start." >&2
  cat "${RESULT_DIR}/echo.log" >&2
  exit 1
fi

if [[ "${PRESSURE}" == "1" ]]; then
  for cpu in 16 17 18 19; do
    taskset -c "${cpu}" bash -c 'while :; do :; done' >/dev/null 2>&1 &
    PRESSURE_PIDS+=("$!")
  done
fi

{
  date --iso-8601=seconds
  echo "experiment=performance"
  echo "mode=${MODE}"
  echo "nic=${NIC}"
  echo "upf_ip=${UPF_IP}"
  echo "gnb_ip=${GNB_IP}"
  echo "upf_cpus=${UPF_CPUS}"
  echo "rps_cpus=$(cat "${RPS_FILE}")"
  echo "target_pps=${TARGET_PPS}"
  echo "duration=${DURATION}"
  echo "receive_grace=${GRACE}"
  echo "cpu_pressure=${PRESSURE}"
} >"${RESULT_DIR}/environment.txt"

ip -s link show dev "${NIC}" >"${RESULT_DIR}/nic-before.txt"
ip -s link show upfgtp >"${RESULT_DIR}/upfgtp-before.txt" 2>&1 || true
if [[ "${MODE}" == "xdp-steering" ]]; then
  "${XDPSTATS}" >"${RESULT_DIR}/xdp-before.txt"
else
  printf 'not available: XDP is detached\n' >"${RESULT_DIR}/xdp-before.txt"
fi

echo
echo "UPF performance endpoint is ready and will remain running."
echo "Run this on 192.168.113.20 (no START_AT required):"
echo "  cd ~/workspace/XT-UPF/go-upf"
echo "  TARGET_PPS=${TARGET_PPS} EXPERIMENT_DURATION=${DURATION} RECEIVE_GRACE=${GRACE} ./scripts/physical_gtpu_sender.sh"
echo
read -r -p "Press Enter only after the sender has printed its result... "

ip -s link show dev "${NIC}" >"${RESULT_DIR}/nic-after.txt"
ip -s link show upfgtp >"${RESULT_DIR}/upfgtp-after.txt" 2>&1 || true
if [[ "${MODE}" == "xdp-steering" ]]; then
  "${XDPSTATS}" >"${RESULT_DIR}/xdp-after.txt"
else
  printf 'not available: XDP is detached\n' >"${RESULT_DIR}/xdp-after.txt"
fi

printf 'UPF result directory: %s\n' "${RESULT_DIR}"
