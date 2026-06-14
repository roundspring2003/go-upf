#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${REPO_ROOT}/bin/xdpstandalone"
NIC="${SENDER_NIC:-enxc84d4423bbe0}"
SRC_IP="${SENDER_IP:-192.168.113.20}"
DST_IP="${UPF_IP:-192.168.113.21}"
DST_MAC="${UPF_MAC:-00:0e:c6:87:a7:02}"
UE_IP="${UE_IP:-10.60.0.1}"
REMOTE_IP="${REMOTE_IP:-1.1.1.1}"
FLOWS="${EXPERIMENT_FLOWS:-1:7:1,1:8:2,1:8:2,1:9:3}"
DURATION="${EXPERIMENT_DURATION:-30}"
START_AT="${START_AT:-0}"

if [[ ! -x "${TOOL}" ]]; then
  if [[ ! -f "${REPO_ROOT}/go.mod" ]]; then
    echo "Missing ${TOOL}; copy the binary from the UPF host or run this script inside the go-upf repository." >&2
    exit 1
  fi
  mkdir -p "${REPO_ROOT}/bin"
  (cd "${REPO_ROOT}" && go build -o "${TOOL}" ./testtools/xdpstandalone)
fi

if ! ip -4 -o addr show dev "${NIC}" | awk '{print $4}' | grep -q "^${SRC_IP}/"; then
  echo "${NIC} does not have ${SRC_IP}." >&2
  ip -br addr show dev "${NIC}" >&2
  exit 1
fi
if ! ping -c 1 -W 1 "${DST_IP}" >/dev/null; then
  echo "UPF ${DST_IP} is not reachable through ${NIC}." >&2
  exit 1
fi

if (( START_AT > 0 )); then
  now="$(date +%s)"
  if (( now < START_AT )); then
    echo "Waiting $((START_AT - now)) seconds; synchronized start=${START_AT}."
    sleep "$((START_AT - now))"
  elif (( now > START_AT + 2 )); then
    echo "START_AT=${START_AT} is already in the past." >&2
    exit 1
  fi
fi

echo "Sending physical GTP-U: ${SRC_IP} (${NIC}) -> ${DST_IP}, duration=${DURATION}s"
exec sudo "${TOOL}" send \
  --interface "${NIC}" \
  --src-ip "${SRC_IP}" \
  --dst-ip "${DST_IP}" \
  --dst-mac "${DST_MAC}" \
  --ue-ip "${UE_IP}" \
  --remote-ip "${REMOTE_IP}" \
  --flows "${FLOWS}" \
  --duration "${DURATION}s"
