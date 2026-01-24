#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct exec_stats {
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct exec_stats);
} execve_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx)
{
    __u32 key = 0;
    struct exec_stats *s = bpf_map_lookup_elem(&execve_map, &key);
    if (s)
        __sync_fetch_and_add(&s->count, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
