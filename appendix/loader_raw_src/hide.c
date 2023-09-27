#include "hide.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

//#include <bpf/bpf.h>

#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/version.h>


#define INSTRUCTION_COUNT 11
#define INSTRUCTION_SIZE 8
#define GETDENTS64_ID 845


int main() {

    int ret;
    long int rret;
    ssize_t rdwr;

    //allocate log buffer
    char * log_buf = malloc(16000);
    if (log_buf == NULL) { perror("malloc log_buf"); return -1; }
    memset(log_buf, 0, 16000);
    
    //allocate buffer for instructions
    char * insns_buf = malloc(INSTRUCTION_COUNT * INSTRUCTION_SIZE);
    if (insns_buf == NULL) { fprintf(stderr, "malloc error.\n"); return -1; }

    //open object file
    int insns_fd = open("./prog.o", O_RDONLY);
    if (insns_fd == -1) { perror("open error"); return -1; }

    //fill instruction buffer
    if (read(insns_fd, insns_buf, INSTRUCTION_COUNT * INSTRUCTION_SIZE) == -1) { 
        fprintf(stderr, "malloc error.\n"); return -1; }
    close(insns_fd);

    //insert readonly map
    int romap_fd;
    union bpf_attr map_attr;
    memset(&map_attr, 0, sizeof(map_attr));
    map_attr.map_type=BPF_MAP_TYPE_ARRAY;
    map_attr.key_size=4;
    map_attr.value_size=20;
    map_attr.max_entries=1;
    map_attr.map_flags=BPF_F_RDONLY_PROG;
    strcpy(map_attr.map_name, "uwudata");
    
    romap_fd = syscall(__NR_bpf, BPF_MAP_CREATE, &map_attr, sizeof(map_attr));
    if (romap_fd == -1) {
        perror("bpf BPF_MAP_CREATE");
        return -1;
    }


    //insert into map
    union bpf_attr str_attr;
    int key = 0;
    char * value = "hello world!\n\0\0\0\0\0\0\0";
    memset(&str_attr, 0, sizeof(str_attr));
    str_attr.map_fd = romap_fd;
    str_attr.key = &key;
    str_attr.value = &value;
    str_attr.flags = BPF_ANY;
    
    ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &str_attr, 32);
    if (ret == -1) {
        perror("bpf BPF_MAP_UPDATE_ELEM");
        return -1;
    }


    //freeze map
    union bpf_attr frz_attr;
    frz_attr.map_fd = romap_fd;

    ret = syscall(__NR_bpf, BPF_MAP_FREEZE, &frz_attr, 4);
    if (ret == -1) {
        perror("bpf BPF_MAP_FREEZE");
        return -1;
    }


    //load the bpf program
    int prog_fd;
    union bpf_attr load_attr;
    int fd_array[1];
    fd_array[0] = romap_fd;
    memset(&load_attr, 0, sizeof(load_attr));
    load_attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
    load_attr.insn_cnt = INSTRUCTION_COUNT;
    load_attr.insns = (__aligned_u64) insns_buf;
    load_attr.license = "GPL";
    load_attr.fd_array = fd_array;

    strcpy(load_attr.prog_name, "owofier");

    load_attr.log_level = 3;
    load_attr.log_size = 16000;
    load_attr.log_buf = log_buf;

    prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &load_attr, sizeof(load_attr));
    printf("log_buf:\n %s\n", log_buf);
    if (prog_fd == -1) {
        perror("bpf BPF_PROG_LOAD");
        return -1;
    }


    //open performance event
    int perf_fd;
    struct perf_event_attr pe = {
        .type = PERF_TYPE_TRACEPOINT,
        .size = sizeof(struct perf_event_attr),
        .config = GETDENTS64_ID,

        .sample_period = 0,//1,
        .sample_type = PERF_SAMPLE_RAW,
        .wakeup_events = 1,

        .disabled = 0,
        //.bpf_event = 1
    };

    perf_fd = syscall(__NR_perf_event_open, &pe, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
    if (perf_fd == -1) {
        perror("perf_event_open");
        return -1;
    }
 
    //enable tracepoint      
    ret = ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
    if (ret == -1) {
        perror("ioctl PERF_EVENT_IOC_SET_BPF");
        return -1;
    }
    ret = ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    if (ret == -1) {
        perror("ioctl PERF_EVENT_IOC_ENABLE");
        return -1;
    }

    printf("load complete\n");
    
    //open pipe to read eBPF program output
    int trace_fd;
    trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
    if (trace_fd < 0) {
        fprintf(stderr, "open trace pipe error.\n");
        return -1;
    }
    
    //receive output from eBPF program's calls to printk()
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
