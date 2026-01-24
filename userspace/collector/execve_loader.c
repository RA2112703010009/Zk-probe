#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile bool exiting = false;
static void sig_handler(int sig) { exiting = true; }

int main(void) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link_execve = NULL, *link_execveat = NULL;
    int map_fd;
    __u32 key = 0;
    __u64 value = 0;

    signal(SIGINT, sig_handler);

    /* Absolute path avoids silent failures */
    obj = bpf_object__open_file("/home/ubuntu/Desktop/zk-probe/ebpf/tracepoints/execve_counter.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }

    /* Attach tracepoints */
    prog = bpf_object__find_program_by_name(obj, "trace_execve");
    link_execve = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_execve");
    if (libbpf_get_error(link_execve)) {
        fprintf(stderr, "Failed to attach tracepoint sys_enter_execve\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "trace_execveat");
    link_execveat = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_execveat");
    if (libbpf_get_error(link_execveat)) {
        fprintf(stderr, "Failed to attach tracepoint sys_enter_execveat\n");
        return 1;
    }

    /* Find map fd */
    map_fd = bpf_object__find_map_fd_by_name(obj, "execve_counts");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find map\n");
        return 1;
    }

    printf("Execve counter running (Ctrl+C to stop)...\n");

    while (!exiting) {
        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0)
            printf("execve calls: %" PRIu64 "\n", (uint64_t)value);
        sleep(1);
    }

    bpf_link__destroy(link_execve);
    bpf_link__destroy(link_execveat);
    bpf_object__close(obj);
    return 0;
}
