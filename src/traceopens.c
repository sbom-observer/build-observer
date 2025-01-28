#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include "../bpf/headers/traceopens.h"
#include "traceopens.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    
    switch (e->type) {
        case 1:
            printf("exec\t%s\n", e->filename);
            break;
        case 2:
            printf("open\t%s\t%s\n", e->comm, e->filename);
            break;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct traceopens_bpf *skel;
    int err;
    pid_t child_pid;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    /* Open BPF application */
    skel = traceopens_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = traceopens_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoints */
    err = traceopens_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Set up ring buffer */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("start ");
    time_t now = time(NULL);
    printf("%s", ctime(&now));

    /* Fork and execute the command */
    child_pid = fork();
    if (child_pid < 0) {
        fprintf(stderr, "Failed to fork\n");
        goto cleanup;
    }

    if (child_pid == 0) {
        /* Child process */
        execvp(argv[1], &argv[1]);
        /* If we get here, execvp failed */
        fprintf(stderr, "Failed to execute %s\n", argv[1]);
        exit(1);
    }

    /* Add the child PID to the map for tracking */
    int map_fd = bpf_map__fd(skel->maps.pids);
    __u8 value = 1;
    err = bpf_map_update_elem(map_fd, &child_pid, &value, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to add child PID to map\n");
        goto cleanup;
    }

    /* Handle signals */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Main loop */
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            goto cleanup;
        }

        /* Check if the child process has finished */
        int status;
        pid_t ret = waitpid(child_pid, &status, WNOHANG);
        if (ret == child_pid) {
            printf("Child process exited with status %d\n", 
                   WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            break;
        }
    }

    printf("stop ");
    now = time(NULL);
    printf("%s", ctime(&now));

cleanup:
    ring_buffer__free(rb);
    traceopens_bpf__destroy(skel);
    return err != 0;
}
