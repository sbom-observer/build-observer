#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>

#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 16
#define MAX_PIDS 1024

static volatile int exiting = 0;
static pid_t traced_pids[MAX_PIDS];
static int num_pids = 0;

// Track syscall state for each process
struct pid_state {
    pid_t pid;
    int in_syscall;  // 1 if we're entering syscall, 0 if exiting
    long syscall;    // Current syscall number
};

static struct pid_state pid_states[MAX_PIDS];

static void sig_handler(int sig) {
    exiting = 1;
}

// Add a PID to our tracking array
static void add_pid(pid_t pid) {
    if (num_pids < MAX_PIDS) {
        traced_pids[num_pids] = pid;
        pid_states[num_pids].pid = pid;
        pid_states[num_pids].in_syscall = 0;
        pid_states[num_pids].syscall = -1;
        num_pids++;
    }
}

// Remove a PID from our tracking array
static void remove_pid(pid_t pid) {
    for (int i = 0; i < num_pids; i++) {
        if (traced_pids[i] == pid) {
            traced_pids[i] = traced_pids[num_pids - 1];
            pid_states[i] = pid_states[num_pids - 1];
            num_pids--;
            break;
        }
    }
}

// Find state for a given PID
static struct pid_state *find_pid_state(pid_t pid) {
    for (int i = 0; i < num_pids; i++) {
        if (pid_states[i].pid == pid) {
            return &pid_states[i];
        }
    }
    return NULL;
}

// Read string from traced process memory
static int read_string(pid_t pid, unsigned long addr, char *str, size_t len) {
    size_t i = 0;
    unsigned long word;

    while (i < len - 1) {
        word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
        if (word == -1 && errno) {
            return -1;
        }

        for (size_t j = 0; j < sizeof(word); j++) {
            char c = ((char*)&word)[j];
            str[i + j] = c;
            if (c == '\0') {
                return 0;
            }
        }
        i += sizeof(word);
    }
    str[len - 1] = '\0';
    return 0;
}

// Get process name from /proc
static void get_proc_name(pid_t pid, char *name, size_t len) {
    char path[32];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    
    FILE *f = fopen(path, "r");
    if (f) {
        if (fgets(name, len, f)) {
            name[strcspn(name, "\n")] = 0;
        } else {
            snprintf(name, len, "<unknown>");
        }
        fclose(f);
    } else {
        snprintf(name, len, "<unknown>");
    }
}

// Handle a single traced process
static void handle_syscall(pid_t pid, struct pid_state *state) {
    struct user_regs_struct regs;
    char pathname[MAX_PATH_LEN];
    char comm[MAX_COMM_LEN];

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        return;
    }

    if (!state->in_syscall) {
        // Syscall entry
#ifdef __x86_64__
        state->syscall = regs.orig_rax;
#else
        state->syscall = regs.orig_eax;
#endif
        state->in_syscall = 1;

        switch (state->syscall) {
            case SYS_openat: {
#ifdef __x86_64__
                unsigned long path_ptr = regs.rsi;
#else
                unsigned long path_ptr = regs.edx;
#endif
                if (read_string(pid, path_ptr, pathname, sizeof(pathname)) == 0) {
                    get_proc_name(pid, comm, sizeof(comm));
                    printf("open\t%s\t%s\n", comm, pathname);
                }
                break;
            }
            case SYS_execve: {
#ifdef __x86_64__
                unsigned long path_ptr = regs.rdi;
#else
                unsigned long path_ptr = regs.ebx;
#endif
                if (read_string(pid, path_ptr, pathname, sizeof(pathname)) == 0) {
                    printf("exec\t%s\n", pathname);
                }
                break;
            }
        }
    } else {
        // Syscall exit
        state->in_syscall = 0;
    }
}

int main(int argc, char **argv) {
    pid_t child;
    int status;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    printf("start ");
    time_t now = time(NULL);
    printf("%s", ctime(&now));

    child = fork();
    if (child == 0) {
        // Child process
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[1], &argv[1]);
        fprintf(stderr, "Failed to execute %s\n", argv[1]);
        exit(1);
    }

    // Parent process
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Add initial child to tracking
    add_pid(child);

    // Wait for child to stop on its first instruction
    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, 0,
           PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
           PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
           PTRACE_O_TRACEEXEC);
    ptrace(PTRACE_SYSCALL, child, 0, 0);

    while (!exiting && num_pids > 0) {
        // Wait for any child to stop
        pid_t pid = waitpid(-1, &status, __WALL);
        // printf("waitpid: %d\n", pid);
        if (pid == -1) {
            if (errno == ECHILD) {
                break;  // No more children
            }
            continue;
        }

        // Handle fork/clone/vfork events
        if (status >> 16) {
            printf("fork/clone/vfork event\n");
            unsigned long new_pid;
            if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid) != -1) {
                printf("new_pid: %d\n", new_pid);
                // Add new process to our tracking list
                add_pid(new_pid);
                // Set options for the new process
                ptrace(PTRACE_SETOPTIONS, new_pid, 0,
                       PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                       PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                       PTRACE_O_TRACEEXEC);
                // Continue both processes
                ptrace(PTRACE_SYSCALL, new_pid, 0, 0);
                ptrace(PTRACE_SYSCALL, pid, 0, 0);

                printf("after fork/clone/vfork event\n");
                continue;
            }
        }

        // Check if process has exited
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            remove_pid(pid);
            continue;
        }

        // Handle syscall entry/exit
        if (WIFSTOPPED(status)) {
            struct pid_state *state = find_pid_state(pid);
            // printf("syscall event\n");
            if (state) {
                handle_syscall(pid, state);
            }
            
            if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
                if (errno == ESRCH) {
                    remove_pid(pid);
                }
            }
        }
    }

    printf("stop ");
    now = time(NULL);
    printf("%s", ctime(&now));

    // Clean up any remaining processes
    for (int i = 0; i < num_pids; i++) {
        kill(traced_pids[i], SIGTERM);
    }

    return 0;
} 