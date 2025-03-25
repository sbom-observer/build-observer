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

/*
 * Using raw_tracepoint/sched_process_exec instead of tp/syscalls/sys_enter_execve + sys_exit_execve
 * for two main reasons:
 * 
 * 1. It provides access to the fully resolved path that the kernel actually executes.
 *    When execve is called with a relative path or just a filename (like "ls"), 
 *    the kernel performs PATH resolution during the syscall to find the actual 
 *    executable (like "/bin/ls"). This tracepoint fires after that resolution,
 *    giving us the real path that was executed.
 * 2. It fires at the right moment after successful execution, eliminating the need for
 *    enter/exit handler pairs and temporary maps to pass data between them
 * 
 * This is particularly important because by the time we try to resolve paths in userspace,
 * short-lived processes might have already terminated, making their /proc entries 
 * inaccessible for path resolution.
 * 
 * However, tp/syscalls/sys_enter_execve + sys_exit_execve might be more stable across kernels.
 */
SEC("raw_tracepoint/sched_process_exec")
int handle_exec(struct bpf_raw_tracepoint_args *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u8 *exists = bpf_map_lookup_elem(&pids, &pid);
    if (!exists)
        return 0;

    // Safely read the filename pointer from args
    struct filename *fn;
    bpf_probe_read_kernel(&fn, sizeof(fn), &ctx->args[1]);
    
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    // Fill event data
    e->pid = pid;
    e->type = 1; // exec
    
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    
    // Safely read the path from the filename structure
    const char *name;
    bpf_probe_read_kernel(&name, sizeof(name), &fn->name);
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), name);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
