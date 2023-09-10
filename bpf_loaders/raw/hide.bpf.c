#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


struct bpf_map_def SEC("maps") uwudata = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = 20,
    .max_entries = 1
};


SEC("tracepoint/syscalls/sys_enter_execve")
int hello_world(void * ctx) {

    u32 key = 0;
    char * print_str = bpf_map_lookup_elem(&uwudata, &key);

    bpf_trace_printk(print_str, 20);
    return 0;
}
