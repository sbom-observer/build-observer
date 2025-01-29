#ifndef __TRACEOPENS_H
#define __TRACEOPENS_H

// Max path length for file names
#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 16

struct event {
    __u32 pid;
    __u32 ppid;
    __s32 dirfd; 
    char comm[MAX_COMM_LEN];
    char filename[MAX_PATH_LEN];
    __u8 type;  // 1 = exec, 2 = open
};

#endif /* __TRACEOPENS_H */ 