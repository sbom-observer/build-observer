#include "vmlinux.h"
// #include <linux/bpf.h>
// #include <sys/types.h> 
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
    __type(value, struct {
        int dirfd;
        char filename[MAX_PATH_LEN];
    });
} path_map SEC(".maps");

// Per-CPU array for event data
// struct {
//     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//     __uint(max_entries, 1);
//     __type(key, u32);
//     __type(value, struct event);
// } heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, char[MAX_PATH_LEN]);
} exec_map SEC(".maps");

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

    const char *user_filename;
    int dirfd;

    // Get both dirfd and filename
    dirfd = (int)BPF_CORE_READ(ctx, args[0]);
    user_filename = (const char *)BPF_CORE_READ(ctx, args[1]);

    // Store both in the path_map
    struct {
        int dirfd;
        char filename[MAX_PATH_LEN];
    } path_info = {
        .dirfd = dirfd
    };
    
    bpf_probe_read_user_str(path_info.filename, sizeof(path_info.filename), user_filename);
    bpf_map_update_elem(&path_map, &pid, &path_info, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    int ret = ctx->ret;
    
    if (ret < 0)
        goto cleanup;

    struct {
        int dirfd;
        char filename[MAX_PATH_LEN];
    } *path_info = bpf_map_lookup_elem(&path_map, &pid);
    if (!path_info)
        goto cleanup;

    // Reserve space in the ring buffer
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        goto cleanup;

    // Fill event data
    e->pid = pid;
    e->type = 2; // open
    e->dirfd = path_info->dirfd;  // Include dirfd in the event
    
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memcpy(e->filename, path_info->filename, MAX_PATH_LEN);
    
    // Submit event to ring buffer
    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&path_map, &pid);
    return 0;
}

SEC("tp/syscalls/sys_enter_execve")
int handle_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u8 *exists = bpf_map_lookup_elem(&pids, &pid);
    if (!exists)
        return 0;

    char filename[MAX_PATH_LEN];
    const char *user_filename = (const char *)BPF_CORE_READ(ctx, args[0]);
    
    bpf_probe_read_user_str(filename, sizeof(filename), user_filename);
    bpf_map_update_elem(&exec_map, &pid, filename, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_execve")
int handle_execve_exit(struct trace_event_raw_sys_exit *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    int ret = ctx->ret;
    
    if (ret < 0)
        goto cleanup;

    char *path = bpf_map_lookup_elem(&exec_map, &pid);
    if (!path)
        goto cleanup;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        goto cleanup;

    // Fill event data
    e->pid = pid;
    e->type = 1; // exec
    
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memcpy(e->filename, path, MAX_PATH_LEN);
    
    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&exec_map, &pid);
    return 0;
}
