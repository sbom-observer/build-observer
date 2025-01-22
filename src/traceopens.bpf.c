#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "traceopens.h"

char LICENSE[] SEC("license") = "GPL";

// Maps to track state
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, u8);
} pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// Temporary maps for passing data between enter and exit
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, char[MAX_PATH_LEN]);
} path_map SEC(".maps");

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    pid_t parent_pid = BPF_CORE_READ(ctx, parent_pid);
    pid_t child_pid = BPF_CORE_READ(ctx, child_pid);
    u8 *exists;

    exists = bpf_map_lookup_elem(&pids, &parent_pid);
    if (exists) {
        u8 val = 1;
        bpf_map_update_elem(&pids, &child_pid, &val, BPF_ANY);
    }

    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u8 *exists = bpf_map_lookup_elem(&pids, &pid);
    if (!exists)
        return 0;

    const char *filename = (const char *)ctx->args[1];
    bpf_map_update_elem(&path_map, &pid, (void *)filename, BPF_ANY);
    
    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    int ret = ctx->ret;
    
    if (ret < 0)
        goto cleanup;

    char *path = bpf_map_lookup_elem(&path_map, &pid);
    if (!path)
        goto cleanup;

    struct event e = {};
    e.pid = pid;
    e.type = 2; // open
    
    bpf_get_current_comm(e.comm, sizeof(e.comm));
    bpf_probe_read_user_str(e.filename, sizeof(e.filename), path);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

cleanup:
    bpf_map_delete_elem(&path_map, &pid);
    return 0;
} 