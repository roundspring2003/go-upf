#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
NIC="${E2E_NIC:-enx000ec687a702}"
UPF_IP="${E2E_UPF_IP:-192.168.113.21}"
GNB_IP="${GNB_IP:-192.168.113.20}"
UPF_CPUS="${UPF_CPUS:-16-19}"
DURATION="${EXPERIMENT_DURATION:-30}"
START_DELAY="${START_DELAY:-20}"
FLOWS="${EXPERIMENT_FLOWS:-1:7:1,1:8:2,1:8:2,1:9:3}"
QOS_FLOWS="${MOCK_QOS_FLOWS:-7:1,8:2,9:3}"
PRESSURE="${CPU_PRESSURE:-0}"
RESULT_ROOT="${PHYSICAL_RESULT_ROOT:-${REPO_ROOT}/experiments}"
RESULT_DIR="${RESULT_ROOT}/physical-${MODE}-$(date +%Y%m%d-%H%M%S)"
UPFTEST="${REPO_ROOT}/bin/upftest"
XDPTOOL="${REPO_ROOT}/bin/xdpstandalone"
RPS_FILE="/sys/class/net/${NIC}/queues/rx-0/rps_cpus"
PRESSURE_PIDS=()
ORIGINAL_RPS=""
DATA_CPUS=""

expand_cpu_list() {
  python3 - "${UPF_CPUS}" <<'PYCPU'
import sys
cpus = []
for item in sys.argv[1].split(','):
    item = item.strip()
    if '-' in item:
        start, end = map(int, item.split('-', 1))
        cpus.extend(range(start, end + 1))
    elif item:
        cpus.append(int(item))
print(','.join(str(cpu) for cpu in sorted(set(cpus))))
PYCPU
}

usage() {
  echo "Usage: $0 {native|xdp-steering}" >&2
}

case "${MODE}" in
  native) XDP_ENABLED=0 ;;
  xdp-steering) XDP_ENABLED=1 ;;
  *) usage; exit 2 ;;
esac
TARGET_RPS=0

DATA_CPUS="$(expand_cpu_list)"
if [[ -z "${DATA_CPUS}" ]]; then
  echo "UPF_CPUS resolved to an empty CPU list." >&2
  exit 1
fi
if [[ "${EUID}" -eq 0 ]]; then
  echo "Run as the normal user; the script invokes sudo where required." >&2
  exit 1
fi
if [[ ! -w "${RESULT_ROOT}" ]]; then
  mkdir -p "${RESULT_ROOT}"
fi
if [[ ! -f "${RPS_FILE}" ]]; then
  echo "Expected one RX queue at ${RPS_FILE}, but it was not found." >&2
  exit 1
fi
if [[ "$(find "/sys/class/net/${NIC}/queues" -maxdepth 1 -type d -name 'rx-*' | wc -l)" -ne 1 ]]; then
  echo "This experiment expects exactly one RX queue on ${NIC}." >&2
  exit 1
fi

mkdir -p "${REPO_ROOT}/bin" "${RESULT_DIR}"
(cd "${REPO_ROOT}" && go build -o bin/upf ./cmd/main.go)
(cd "${REPO_ROOT}" && go build -o bin/upftest ./testtools/upftest)
(cd "${REPO_ROOT}" && go build -o bin/xdpstandalone ./testtools/xdpstandalone)
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
  "${REPO_ROOT}/scripts/e2e_upf_stop.sh" || true
  if [[ -n "${ORIGINAL_RPS}" && -f "${RPS_FILE}" ]]; then
    printf '%s\n' "${ORIGINAL_RPS}" | sudo tee "${RPS_FILE}" >/dev/null || true
  fi
}
trap cleanup EXIT

if ! printf '%s\n' "${TARGET_RPS}" | sudo tee "${RPS_FILE}" >/dev/null; then
  echo "Failed to disable RPS on ${NIC}." >&2
  exit 1
fi

E2E_XDP="${XDP_ENABLED}" E2E_NIC="${NIC}" E2E_UPF_IP="${UPF_IP}" \
  E2E_SMF_IP="${GNB_IP}" UPF_CPUS="${UPF_CPUS}" \
  "${REPO_ROOT}/scripts/e2e_upf_start.sh"

UPF_PID="$(cat "${REPO_ROOT}/e2e/run/upf.pid")"
"${UPFTEST}" \
  -s "${UPF_IP}:8805" \
  -n "${GNB_IP}" \
  -ue-ip 10.60.0.1 \
  -access-teid 1 \
  -access-ip "${GNB_IP}" \
  -dl-teid 2 \
  -dl-peer-ip "${GNB_IP}" \
  -qos-flows "${QOS_FLOWS}" >"${RESULT_DIR}/mock-smf.log" 2>&1

if [[ "${PRESSURE}" == "1" ]]; then
  IFS=',' read -ra pressure_cpus <<<"${DATA_CPUS}"
  for cpu in "${pressure_cpus[@]}"; do
    taskset -c "${cpu}" bash -c 'while :; do :; done' >/dev/null 2>&1 &
    PRESSURE_PIDS+=("$!")
  done
fi

START_AT=$(( $(date +%s) + START_DELAY ))
{
  date --iso-8601=seconds
  uname -a
  echo "mode=${MODE}"
  echo "nic=${NIC}"
  echo "upf_ip=${UPF_IP}"
  echo "gnb_ip=${GNB_IP}"
  echo "upf_cpus=${UPF_CPUS}"
  echo "data_cpus=${DATA_CPUS}"
  echo "rps_cpus=$(cat "${RPS_FILE}")"
  echo "duration=${DURATION}"
  echo "start_at=${START_AT}"
  echo "cpu_pressure=${PRESSURE}"
  ip -details link show dev "${NIC}"
  ethtool -l "${NIC}" 2>&1 || true
  taskset -pc "${UPF_PID}"
} >"${RESULT_DIR}/environment.txt"

ip -s link show dev "${NIC}" >"${RESULT_DIR}/nic-before.txt"
ip -s link show upfgtp >"${RESULT_DIR}/upfgtp-before.txt" 2>&1 || true
cp /proc/softirqs "${RESULT_DIR}/softirqs-before.txt"
if [[ "${MODE}" == "xdp-steering" ]]; then
  "${XDPTOOL}" stats >"${RESULT_DIR}/xdp-before.txt"
  bpftool map dump pinned /sys/fs/bpf/xdp/globals/ul_flow_qos_map >"${RESULT_DIR}/ul-flow-map.txt" 2>&1 || true
else
  printf 'not available: XDP is detached\n' >"${RESULT_DIR}/xdp-before.txt"
fi

echo
echo "Run this on 192.168.113.20 now:"
echo "  cd ~/workspace/XT-UPF/go-upf"
echo "  START_AT=${START_AT} EXPERIMENT_DURATION=${DURATION} ./scripts/physical_gtpu_sender.sh"
echo "Synchronized start is $(date -d "@${START_AT}" --iso-8601=seconds)."

now="$(date +%s)"
if (( now < START_AT )); then sleep "$((START_AT - now))"; fi
mpstat -P "${DATA_CPUS}" 1 "${DURATION}" >"${RESULT_DIR}/mpstat.txt" &
MPSTAT_PID=$!
pidstat -p "${UPF_PID}" -t 1 "${DURATION}" >"${RESULT_DIR}/pidstat.txt" &
PIDSTAT_PID=$!
wait "${MPSTAT_PID}"
wait "${PIDSTAT_PID}"

cp /proc/softirqs "${RESULT_DIR}/softirqs-after.txt"
ip -s link show dev "${NIC}" >"${RESULT_DIR}/nic-after.txt"
ip -s link show upfgtp >"${RESULT_DIR}/upfgtp-after.txt" 2>&1 || true
ethtool -S "${NIC}" >"${RESULT_DIR}/ethtool-stats.txt" 2>&1 || true
if [[ "${MODE}" == "xdp-steering" ]]; then
  "${XDPTOOL}" stats >"${RESULT_DIR}/xdp-after.txt"
else
  printf 'not available: XDP is detached\n' >"${RESULT_DIR}/xdp-after.txt"
fi

grep '^Average:' "${RESULT_DIR}/mpstat.txt" >"${RESULT_DIR}/cpu-average.txt" || true
printf 'Result directory: %s\n' "${RESULT_DIR}"
cat "${RESULT_DIR}/cpu-average.txt"
