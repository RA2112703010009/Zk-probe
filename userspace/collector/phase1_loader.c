#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <net/if.h>

#include <openssl/sha.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

struct zk_flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 syn;
};

struct phase1_snapshot {
    __u64 timestamp_ns;
    __u64 execve_count;
    __u32 flow_count;
    __u64 total_packets;
    __u64 total_bytes;
    __u64 syn_packets;
    unsigned char hash[32];
};

static void hash_snapshot(struct phase1_snapshot *s)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    SHA256_Update(&ctx, &s->timestamp_ns, sizeof(s->timestamp_ns));
    SHA256_Update(&ctx, &s->execve_count, sizeof(s->execve_count));
    SHA256_Update(&ctx, &s->flow_count, sizeof(s->flow_count));
    SHA256_Update(&ctx, &s->total_packets, sizeof(s->total_packets));
    SHA256_Update(&ctx, &s->total_bytes, sizeof(s->total_bytes));
    SHA256_Update(&ctx, &s->syn_packets, sizeof(s->syn_packets));

    SHA256_Final(s->hash, &ctx);
}

int main(void)
{
    signal(SIGINT, sig_handler);

    /* ---- Open execve_counter BPF object ---- */
    struct bpf_object *exec_obj;
    exec_obj = bpf_object__open_file("../../build/bpf/execve_counter.bpf.o", NULL);
    if (libbpf_get_error(exec_obj)) {
        fprintf(stderr, "Failed to open execve_counter BPF object\n");
        return 1;
    }
    if (bpf_object__load(exec_obj)) {
        fprintf(stderr, "Failed to load execve_counter BPF object\n");
        return 1;
    }
    struct bpf_link *tp_link = bpf_program__attach_tracepoint(
        bpf_object__find_program_by_name(exec_obj, "trace_execve"),
        "syscalls", "sys_enter_execve"
    );
    int exec_fd = bpf_object__find_map_fd_by_name(exec_obj, "execve_map");

    /* ---- Open xdp_counter BPF object ---- */
    struct bpf_object *xdp_obj;
    xdp_obj = bpf_object__open_file("../../build/bpf/xdp_counter.bpf.o", NULL);
    if (libbpf_get_error(xdp_obj)) {
        fprintf(stderr, "Failed to open xdp_counter BPF object\n");
        return 1;
    }
    if (bpf_object__load(xdp_obj)) {
        fprintf(stderr, "Failed to load xdp_counter BPF object\n");
        return 1;
    }
    int ifindex = if_nametoindex("ens33");
    struct bpf_link *xdp_link = bpf_program__attach_xdp(
        bpf_object__find_program_by_name(xdp_obj, "xdp_counter"),
        ifindex
    );
    int flow_fd = bpf_object__find_map_fd_by_name(xdp_obj, "flow_map");

    printf("Phase-1 invariant collector running\n");

    while (!exiting) {
        struct phase1_snapshot snap = {0};
        struct timespec ts;

        clock_gettime(CLOCK_MONOTONIC, &ts);
        snap.timestamp_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

        /* ---- execve map ---- */
        __u32 key = 0;
        bpf_map_lookup_elem(exec_fd, &key, &snap.execve_count);

        /* ---- flow map ---- */
        __u32 cur = 0, next;
        struct zk_flow_stats stats;

        while (bpf_map_get_next_key(flow_fd, &cur, &next) == 0) {
            if (bpf_map_lookup_elem(flow_fd, &next, &stats) == 0) {
                snap.flow_count++;
                snap.total_packets += stats.packets;
                snap.total_bytes += stats.bytes;
                snap.syn_packets += stats.syn;
            }
            cur = next;
        }

        hash_snapshot(&snap);

        printf(
            "T=%" PRIu64 " execve=%" PRIu64
            " flows=%" PRIu64 " packets=%" PRIu64
            " bytes=%" PRIu64 " syn=%" PRIu64 "\n",
            (uint64_t)snap.timestamp_ns,
            (uint64_t)snap.execve_count,
            (uint64_t)snap.flow_count,
            (uint64_t)snap.total_packets,
            (uint64_t)snap.total_bytes,
            (uint64_t)snap.syn_packets
        );

        printf("hash=");
        for (int i = 0; i < 32; i++)
            printf("%02x", snap.hash[i]);
        printf("\n\n");

        sleep(1);
    }

    bpf_link__destroy(tp_link);
    bpf_link__destroy(xdp_link);
    bpf_object__close(exec_obj);
    bpf_object__close(xdp_obj);

    return 0;
}
