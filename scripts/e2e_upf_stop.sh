#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${REPO_ROOT}/e2e/run"
UPF_BIN="${REPO_ROOT}/bin/upf"
XDP_MARKER="${RUN_DIR}/xdp.nic"

status=0

if [[ -f "${RUN_DIR}/upf.pid" ]]; then
  pid="$(cat "${RUN_DIR}/upf.pid")"
  sudo kill "${pid}" 2>/dev/null || true
  rm -f "${RUN_DIR}/upf.pid"
fi

pids="$(pgrep -f "^${UPF_BIN}( |$)" || true)"
[[ -z "${pids}" ]] || sudo kill ${pids} 2>/dev/null || true

for _ in $(seq 1 100); do
  if ! pgrep -f "^${UPF_BIN}( |$)" >/dev/null; then
    break
  fi
  sleep 0.1
done

if pgrep -f "^${UPF_BIN}( |$)" >/dev/null; then
  printf 'XT-UPF did not stop cleanly:\n' >&2
  pgrep -af "^${UPF_BIN}( |$)" >&2 || true
  status=1
fi

if [[ -f "${XDP_MARKER}" ]]; then
  nic="$(cat "${XDP_MARKER}")"
  if ! sudo "${REPO_ROOT}/scripts/ebpf_nic.sh" down "${nic}"; then
    status=1
  fi
  rm -f "${XDP_MARKER}"
fi

exit "${status}"
