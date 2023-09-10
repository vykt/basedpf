#ifndef __MUTATE_H
#define __MUTATE_H

#include <cstdio>

#include <linux/bpf.h>

#include <random>

#include "type_common.h"
#include "lc_rng.h"

//struct for holding the eBPF program
class ebpf_prog {
    
    private:

        //attributes
        FILE * _fs;

        int _insn_num;                 //number of instructions in insn_buf
        int _insn_avl;                 //space available for instructions
        struct ebpf_insn * _insn_buf;  //instruction buffer

        std::mt19937 _rng;

        //methods
        inline bool can_mutate_insn(struct ebpf_insn * insn);
        inline bool operates_on_reloff(struct ebpf_insn * insn);
        inline int fill_inject_buf(struct bpf_insn * buf, int size);

    public:
        
        //methods
        ebpf_prog(FILE * fs);
        int apply_mutations;
}

#endif
