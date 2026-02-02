//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Map to store blocked IPv4 addresses
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);   // IPv4 address
	__type(value, __u8);  // Dummy value (1 = blocked)
	__uint(max_entries, 1024);
} blocked_ips SEC(".maps");

// Map to count packets (Allowed vs Dropped)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 2); // 0: Allowed, 1: Dropped
} pkt_count SEC(".maps");

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	// 1. Parse Ethernet Header
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}

	// IPv4 Packet Parsing
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return XDP_PASS;
	}

	// Lookup source IP in the blocklist map
	__u32 src_ip = ip->saddr;
	__u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip);

	__u32 key;
	__u64 *value;

	if (blocked) {
		key = 1; // Dropped index
		value = bpf_map_lookup_elem(&pkt_count, &key);
		if (value) __sync_fetch_and_add(value, 1);
		return XDP_DROP;
	}

	key = 0; // Allowed index
	value = bpf_map_lookup_elem(&pkt_count, &key);
	if (value) __sync_fetch_and_add(value, 1);

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
