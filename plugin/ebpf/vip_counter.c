// SPDX-License-Identifier: GPL-2.0
// VIP traffic counter via TC ingress/egress hooks.
// Compiled with: clang -O2 -g -target bpf -I/usr/include/bpf -c vip_counter.c -o vip_counter.o
//
// Hook timing guarantees correctness across all NAT scenarios:
//   TC ingress: runs BEFORE NF PREROUTING -> dst_ip = VIP (pre-DNAT)
//   TC egress:  runs AFTER  NF POSTROUTING -> src_ip = VIP (post-SNAT)

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct vip_stat {
	__u64 packets;
	__u64 bytes;
};

// ── IPv4 maps ────────────────────────────────────────────────────────────────

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __be32);
	__type(value, __u8);
} vip_set SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1024);
	__type(key, __be32);
	__type(value, struct vip_stat);
} vip_ingress_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1024);
	__type(key, __be32);
	__type(value, struct vip_stat);
} vip_egress_stats SEC(".maps");

// ── IPv6 maps ────────────────────────────────────────────────────────────────

struct ipv6_key {
	__u8 addr[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct ipv6_key);
	__type(value, __u8);
} vip_set6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct ipv6_key);
	__type(value, struct vip_stat);
} vip_ingress_stats6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct ipv6_key);
	__type(value, struct vip_stat);
} vip_egress_stats6 SEC(".maps");

// ── IPv4 helpers ─────────────────────────────────────────────────────────────

static __always_inline void
count_ipv4_ingress(struct __sk_buff *skb, __be32 vip)
{
	struct vip_stat *vs = bpf_map_lookup_elem(&vip_ingress_stats, &vip);
	if (vs) {
		vs->packets++;
		vs->bytes += skb->len;
	} else {
		struct vip_stat new_vs = { .packets = 1, .bytes = skb->len };
		bpf_map_update_elem(&vip_ingress_stats, &vip, &new_vs, BPF_NOEXIST);
	}
}

static __always_inline void
count_ipv4_egress(struct __sk_buff *skb, __be32 vip)
{
	struct vip_stat *vs = bpf_map_lookup_elem(&vip_egress_stats, &vip);
	if (vs) {
		vs->packets++;
		vs->bytes += skb->len;
	} else {
		struct vip_stat new_vs = { .packets = 1, .bytes = skb->len };
		bpf_map_update_elem(&vip_egress_stats, &vip, &new_vs, BPF_NOEXIST);
	}
}

// ── IPv6 helpers ─────────────────────────────────────────────────────────────

static __always_inline void
count_ipv6_ingress(struct __sk_buff *skb, struct ipv6_key *key)
{
	struct vip_stat *vs = bpf_map_lookup_elem(&vip_ingress_stats6, key);
	if (vs) {
		vs->packets++;
		vs->bytes += skb->len;
	} else {
		struct vip_stat new_vs = { .packets = 1, .bytes = skb->len };
		bpf_map_update_elem(&vip_ingress_stats6, key, &new_vs, BPF_NOEXIST);
	}
}

static __always_inline void
count_ipv6_egress(struct __sk_buff *skb, struct ipv6_key *key)
{
	struct vip_stat *vs = bpf_map_lookup_elem(&vip_egress_stats6, key);
	if (vs) {
		vs->packets++;
		vs->bytes += skb->len;
	} else {
		struct vip_stat new_vs = { .packets = 1, .bytes = skb->len };
		bpf_map_update_elem(&vip_egress_stats6, key, &new_vs, BPF_NOEXIST);
	}
}

// ── TC ingress: BEFORE NF PREROUTING, dst = VIP ──────────────────────────────
// Return TC_ACT_UNSPEC so this counter does not stop later tc filters such as
// VIP QoS mirred redirects to ifb.

SEC("tc_ingress")
int vip_count_ingress(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_UNSPEC;

	__u16 proto = bpf_ntohs(eth->h_proto);

	if (proto == ETH_P_IP) {
		struct iphdr *ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end)
			return TC_ACT_UNSPEC;
		__u8 *found = bpf_map_lookup_elem(&vip_set, &ip->daddr);
		if (found)
			count_ipv4_ingress(skb, ip->daddr);

	} else if (proto == ETH_P_IPV6) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) > data_end)
			return TC_ACT_UNSPEC;
		struct ipv6_key key;
		__builtin_memcpy(key.addr, &ip6->daddr, 16);
		__u8 *found = bpf_map_lookup_elem(&vip_set6, &key);
		if (found)
			count_ipv6_ingress(skb, &key);
	}

	return TC_ACT_UNSPEC;
}

// ── TC egress: AFTER NF POSTROUTING, src = VIP ───────────────────────────────
// Keep the egress counter non-terminal for future tc actions on the same hook.

SEC("tc_egress")
int vip_count_egress(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_UNSPEC;

	__u16 proto = bpf_ntohs(eth->h_proto);

	if (proto == ETH_P_IP) {
		struct iphdr *ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end)
			return TC_ACT_UNSPEC;
		__u8 *found = bpf_map_lookup_elem(&vip_set, &ip->saddr);
		if (found)
			count_ipv4_egress(skb, ip->saddr);

	} else if (proto == ETH_P_IPV6) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) > data_end)
			return TC_ACT_UNSPEC;
		struct ipv6_key key;
		__builtin_memcpy(key.addr, &ip6->saddr, 16);
		__u8 *found = bpf_map_lookup_elem(&vip_set6, &key);
		if (found)
			count_ipv6_egress(skb, &key);
	}

	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
