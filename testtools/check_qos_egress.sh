#!/usr/bin/env bash
# Read-only checks; run in the same network namespace as the UPF.
set -euo pipefail

if [[ $# -lt 4 || $# -gt 6 ]]; then
    printf 'Usage: bash %s N3_LOCAL_IPV4 GNB_IPV4 UE_IPV4 DN_IPV4 [UL_MARK=1] [GTP_DEVICE=upfgtp]\n' "$0" >&2
    exit 1
fi

for tool in ip tc jq; do
    command -v "$tool" >/dev/null || { printf 'Missing tool: %s\n' "$tool" >&2; exit 1; }
done

n3_local=$1
gnb=$2
ue=$3
dn=$4
ul_mark=${5:-1}
gtp_device=${6:-upfgtp}
for address in "$n3_local" "$gnb" "$ue" "$dn"; do
    if ! jq -en --arg ip "$address" '
        ($ip | test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$")) and
        ($ip | split(".") | all(.[]; (tonumber >= 0 and tonumber <= 255)))
    ' >/dev/null; then
        printf 'Expected an IPv4 address: %s\n' "$address" >&2
        exit 1
    fi
done
if [[ ! $ul_mark =~ ^(0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})$ ]]; then
    printf 'UL_MARK must be a numeric skb mark, including route bits if used.\n' >&2
    exit 1
fi

show_egress() {
    local direction=$1 route=$2 device kind
    printf '\n%s route:\n%s\n' "$direction" "$route"
    device=$(jq -er 'if length == 1 and (.[0].type // "unicast") == "unicast"
        then .[0].dev else empty end' <<<"$route") || {
        printf 'No unique unicast egress for %s.\n' "$direction" >&2
        return 1
    }
    kind=$(ip -j -d link show dev "$device" | jq -r '.[0].linkinfo.info_kind // ""')
    if [[ $device == lo || $device == "$gtp_device" || $kind == gtp5g ]]; then
        printf '%s route selects %s; this is not the external QoS egress.\n' "$direction" "$device" >&2
        return 1
    fi
    printf '%s TC candidate: %s egress (route lookup only; packet verification still required)\n' "$direction" "$device"
    tc qdisc show dev "$device"
    tc class show dev "$device"
    tc filter show dev "$device" egress
}

printf 'Current namespace: '
readlink /proc/self/ns/net
printf '\nRouting rules (check masks against FlowQoS low 24 mark bits):\n'
ip -4 rule show

# Normal DL gtp5g route lookup happens before packet policy marking.
dl_route=$(ip -j -4 route get "$gnb" from "$n3_local")
show_egress DL "$dl_route"

# A local-output route query is not a substitute for forwarded UE traffic.
if ! ip link show dev "$gtp_device" >/dev/null 2>&1; then
    printf '\nUL unresolved: device %s is absent. Run with the UPF active in its network namespace.\n' "$gtp_device" >&2
    exit 2
fi
ul_route=$(ip -j -4 route get "$dn" from "$ue" iif "$gtp_device" mark "$ul_mark")
show_egress UL "$ul_route"
printf '\nRoute/TC inspection complete. No settings changed; no BPF or EDT packet test performed.\n'
