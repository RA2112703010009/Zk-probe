#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

/* ---------- project-owned types ---------- */
struct zk_flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 syn;
};

/* ---------- map ---------- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);              /* src IPv4 */
    __type(value, struct zk_flow_stats);
} flow_map SEC(".maps");

/* ---------- XDP program ---------- */
SEC("xdp")
int xdp_counter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* ---- Ethernet ---- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* ---- IPv4 ---- */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src = ip->saddr;

    /* ---- flow map ---- */
    struct zk_flow_stats *stats;
    stats = bpf_map_lookup_elem(&flow_map, &src);
    if (!stats) {
        struct zk_flow_stats zero = {};
        bpf_map_update_elem(&flow_map, &src, &zero, BPF_ANY);
        stats = bpf_map_lookup_elem(&flow_map, &src);
        if (!stats)
            return XDP_PASS;
    }

    /* ---- counters ---- */
    __sync_fetch_and_add(&stats->packets, 1);
    __sync_fetch_and_add(&stats->bytes, (__u64)(data_end - data));

    /* ---- TCP SYN detection (Phase-1 correct) ---- */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        /* count only initial SYNs */
        if (tcp->syn && !tcp->ack)
            __sync_fetch_and_add(&stats->syn, 1);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
