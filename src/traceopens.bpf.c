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
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB */
} events SEC(".maps");

// Temporary maps for passing data between enter and exit
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, char[MAX_PATH_LEN]);
} path_map SEC(".maps");

// Per-CPU array for event data
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event);
} heap SEC(".maps");

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

    char filename[MAX_PATH_LEN];
    const char *user_filename;

    user_filename = (const char *)BPF_CORE_READ(ctx, args[1]);

    bpf_probe_read_user_str(filename, sizeof(filename), user_filename);
    bpf_map_update_elem(&path_map, &pid, filename, BPF_ANY);

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

    // Reserve space in the ring buffer
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        goto cleanup;

    // Fill event data
    e->pid = pid;
    e->type = 2; // open
    
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memcpy(e->filename, path, MAX_PATH_LEN);
    
    // Submit event to ring buffer
    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&path_map, &pid);
    return 0;
}
