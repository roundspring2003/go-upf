#ifndef __GO_UPF_EBPF_MAPS_H__
#define __GO_UPF_EBPF_MAPS_H__

#include <linux/types.h>

#define QOS_CLASS_LATENCY_SENSITIVE 1
#define QOS_CLASS_STANDARD 2
#define QOS_CLASS_BACKGROUND 3

/* Backward-compatible names for older control-plane tooling. */
#define QOS_CLASS_DELAY_CRITICAL_GBR QOS_CLASS_LATENCY_SENSITIVE
#define QOS_CLASS_STD_GBR QOS_CLASS_STANDARD
#define QOS_CLASS_NON_GBR QOS_CLASS_BACKGROUND

#define XDP_STAT_RX 0
#define XDP_STAT_PASS 1
#define XDP_STAT_UL_HIT 2
#define XDP_STAT_DL_EXACT_HIT 3
#define XDP_STAT_DL_DEFAULT_HIT 4
#define XDP_STAT_QOS_MISS 5
#define XDP_STAT_CPU_SELECT_FAIL 6
#define XDP_STAT_REDIRECT 7
#define XDP_STAT_MAX 8

struct qos_cpu_pool {
	__u32 start_cpu;
	__u32 cpu_count;
};

struct qos_ul_flow_key {
	__u32 teid;
	__u8 qfi;
	__u8 _pad[3];
};

struct qos_dl_flow_key {
	__u32 ue_ipv4;
	__u32 remote_ipv4;
	__u16 ue_port;
	__u16 remote_port;
	__u8 proto;
	__u8 _pad[3];
};

struct qos_flow_info {
	__u8 qfi;
	__u8 _pad[3];
	__u32 qos_class;
};

struct pdr_key {
	__u32 teid;
	__u32 ue_ipv4;
	__u8 src_if;
	__u8 _pad[3];
};

struct pdr_info {
	__u32 far_id;
	__u32 qer_id;
	__u8 need_qos;
	__u8 need_gtp_encap;
	__u8 _pad[2];
};

struct far_info {
	__u8 action;
	__u8 dst_if;
	__u16 outer_header_creation;
	__u32 teid;
	__u32 peer_ipv4;
	__u16 peer_port;
	__u16 _pad;
};

struct qer_info {
	__u8 qfi;
	__u8 gate_status_ul;
	__u8 gate_status_dl;
	__u8 _pad0;
	__u32 mbr_ul;
	__u32 mbr_dl;
	__u32 tc_classid;
};

#endif /* __GO_UPF_EBPF_MAPS_H__ */
