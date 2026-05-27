#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "maps.h"

#define GTPU_PORT 2152
#define GTPU_MSGTYPE_GPDU 255
#define GTPU_FLAG_EXT 0x04
#define GTPU_EXT_PDU_SESSION_CONTAINER 0x85
#define QOS_CPU_MAP_MAX_ENTRIES 256


char __license[] SEC("license") = "Dual BSD/GPL";

struct gtpu_header {
	__u8 flags;
	__u8 msg_type;
	__be16 length;
	__be32 teid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct qos_ul_flow_key);
	__type(value, struct qos_flow_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ul_flow_qos_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct qos_dl_flow_key);
	__type(value, struct qos_flow_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dl_exact_qos_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct qos_flow_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dl_default_qos_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(max_entries, QOS_CPU_MAP_MAX_ENTRIES);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} qos_cpu_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct qos_cpu_pool);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} qos_cpu_pool_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, XDP_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_stats_map SEC(".maps");

static __always_inline void xdp_stats_inc(__u32 stat)
{
	__u64 *counter;

	counter = bpf_map_lookup_elem(&xdp_stats_map, &stat);
	if (counter) {
		__sync_fetch_and_add(counter, 1);
	}
}

static __always_inline int xdp_pass(void)
{
	xdp_stats_inc(XDP_STAT_PASS);
	return XDP_PASS;
}

static __always_inline int qos_class_to_cpu(__u32 qos_class, __u32 flow_hash, __u32 *cpu)
{
	struct qos_cpu_pool *pool;

	pool = bpf_map_lookup_elem(&qos_cpu_pool_map, &qos_class);
	if (!pool || pool->cpu_count == 0) {
		return -1;
	}

	*cpu = pool->start_cpu + (flow_hash % pool->cpu_count);
	return 0;
}

static __always_inline int parse_gtpu_qfi(struct gtpu_header *gtp, void *data_end, __u8 *qfi)
{
	void *opt;
	void *cursor;
	__u8 next_ext;

	if (!(gtp->flags & GTPU_FLAG_EXT)) {
		return -1;
	}

	opt = (void *)(gtp + 1);
	if (opt + 4 > data_end) {
		return -1;
	}

	next_ext = *(__u8 *)(opt + 3);
	cursor = opt + 4;

#pragma unroll
	for (int i = 0; i < 4; i++) {
		__u8 ext_len;
		__u32 ext_bytes;

		if (next_ext == 0) {
			return -1;
		}
		if (cursor + 4 > data_end) {
            return -1; 
        }

		ext_len = *(__u8 *)cursor;
		if (ext_len == 0) {
			return -1;
		}
		ext_bytes = (__u32)ext_len * 4;
		if (cursor + ext_bytes > data_end) {
			return -1;
		}

		if (next_ext == GTPU_EXT_PDU_SESSION_CONTAINER) {
			if (ext_bytes < 4 || cursor + 3 > data_end) {
				return -1;
			}
			*qfi = *(__u8 *)(cursor + 2) & 0x3f;
			if (*qfi == 0) {
				return -1;
			}
			return 0;
		}

		next_ext = *(__u8 *)(cursor + ext_bytes - 1);
		cursor += ext_bytes;
	}

	return -1;
}

SEC("xdp")
int upf_xdp_qos(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct udphdr *udp;
	struct tcphdr *tcp;
	struct gtpu_header *gtp;
	struct qos_flow_info *flow_info;
	__u32 ip_hdr_len;
	__u32 flow_hash;
	__u32 cpu;

	xdp_stats_inc(XDP_STAT_RX);

	if ((void *)(eth + 1) > data_end) {
		return xdp_pass();
	}
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		return xdp_pass();
	}

	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end) {
		return xdp_pass();
	}
	ip_hdr_len = iph->ihl * 4;
	if (ip_hdr_len < sizeof(*iph)) {
		return xdp_pass();
	}
	if ((void *)iph + ip_hdr_len > data_end) {
		return xdp_pass();
	}

	if (iph->protocol == IPPROTO_UDP) {
		udp = (void *)iph + ip_hdr_len;
		if ((void *)(udp + 1) > data_end) {
			return xdp_pass();
		}
		if (udp->dest == bpf_htons(GTPU_PORT)) {
			struct qos_ul_flow_key key = {};

			gtp = (void *)(udp + 1);
			if ((void *)(gtp + 1) > data_end) {
				return xdp_pass();
			}
			if (gtp->msg_type != GTPU_MSGTYPE_GPDU) {
				return xdp_pass();
			}
			if (parse_gtpu_qfi(gtp, data_end, &key.qfi) < 0) {
				return xdp_pass();
			}

			key.teid = bpf_ntohl(gtp->teid);
			flow_info = bpf_map_lookup_elem(&ul_flow_qos_map, &key);
			if (flow_info) {
				xdp_stats_inc(XDP_STAT_UL_HIT);
			}
			flow_hash = key.teid ^ key.qfi;
			goto redirect_by_qos;
		}
	}

	{
		struct qos_dl_flow_key key = {};

		key.ue_ipv4 = bpf_ntohl(iph->daddr);
		key.remote_ipv4 = bpf_ntohl(iph->saddr);
		key.proto = iph->protocol;

		if (iph->protocol == IPPROTO_UDP) {
			udp = (void *)iph + ip_hdr_len;
			if ((void *)(udp + 1) > data_end) {
				return xdp_pass();
			}
			key.ue_port = bpf_ntohs(udp->dest);
			key.remote_port = bpf_ntohs(udp->source);
		} else if (iph->protocol == IPPROTO_TCP) {
			tcp = (void *)iph + ip_hdr_len;
			if ((void *)(tcp + 1) > data_end) {
				return xdp_pass();
			}
			key.ue_port = bpf_ntohs(tcp->dest);
			key.remote_port = bpf_ntohs(tcp->source);
		}

		flow_info = bpf_map_lookup_elem(&dl_exact_qos_map, &key);
		if (flow_info) {
			xdp_stats_inc(XDP_STAT_DL_EXACT_HIT);
		} else {
			flow_info = bpf_map_lookup_elem(&dl_default_qos_map, &key.ue_ipv4);
			if (flow_info) {
				xdp_stats_inc(XDP_STAT_DL_DEFAULT_HIT);
			}
		}
		flow_hash = key.ue_ipv4 ^ key.remote_ipv4 ^ ((__u32)key.ue_port << 16) ^ key.remote_port ^ key.proto;
	}

redirect_by_qos:
	if (!flow_info) {
		xdp_stats_inc(XDP_STAT_QOS_MISS);
		return xdp_pass();
	}

	if (qos_class_to_cpu(flow_info->qos_class, flow_hash, &cpu) < 0) {
		xdp_stats_inc(XDP_STAT_CPU_SELECT_FAIL);
		return xdp_pass();
	}
	xdp_stats_inc(XDP_STAT_REDIRECT);
	return bpf_redirect_map(&qos_cpu_map, cpu, 0);
}
