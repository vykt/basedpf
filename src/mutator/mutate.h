#ifndef __MUTATE_H
#define __MUTATE_H

#include <cstdio>

#include <linux/bpf.h>

#include <random>

#include "type_common.h"
#include "lc_rng.h"


#define NOP_LEN 3

//struct for holding the eBPF program
class ebpf_prog {
    
    private:

        //attributes
        int _insn_num;                 //number of instructions in insn_buf
        int _insn_avl;                 //space available for instructions
        int _insn_usd;                 //number of instructions ultimately used
        struct bpf_insn * _insn_buf;  //instruction buffer

        std::mt19937 * _rng;                    //rng engine
        std::vector<injection> _mutate_metainf; //saved mutation metadata

        //methods
        inline bool can_mutate_insn(struct bpf_insn * insn);
        inline bool operates_on_reloff(struct bpf_insn * insn);
        inline void patch_null(struct bpf_insn * insn);
        inline int fill_inject_buf(struct bpf_insn * buf, int size);

    public:
        
        //methods
        ebpf_prog(FILE * fs);
        int apply_mutations();
        int save_prog(FILE * fs);
        int save_metainf(FILE * fs);
};

#endif
