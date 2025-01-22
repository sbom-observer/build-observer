#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "traceopens.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
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
}

int main(int argc, char **argv)
{
    struct perf_buffer *pb = NULL;
    struct traceopens_bpf *skel;
    int err;

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

    /* Set up perf buffer */
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64,
                         handle_event, NULL, NULL, NULL);
    if (!pb) {
        err = -1;
        fprintf(stderr, "Failed to create perf buffer\n");
        goto cleanup;
    }

    printf("start ");
    time_t now = time(NULL);
    printf("%s", ctime(&now));

    /* Handle signals */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Main loop */
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            goto cleanup;
        }
    }

    printf("stop ");
    now = time(NULL);
    printf("%s", ctime(&now));

cleanup:
    perf_buffer__free(pb);
    traceopens_bpf__destroy(skel);
    return err != 0;
}
