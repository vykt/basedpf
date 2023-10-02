#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>

#include <unistd.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <vector>
#include <stdexcept>
#include <algorithm>
#include <random>

#include "mutate.h"
#include "type_common.h"
#include "config.h"


sbyte nop_insn[NOP_LEN][sizeof(struct bpf_insn)] {
    {'\x07','\x03','\x00','\x00','\x00','\x00','\x00','\x00'}, //add64 r3, 0
    {'\xbf','\x22','\x00','\x00','\x00','\x00','\x00','\x00'}, //mov64 r2, r2
    {'\x17','\x04','\x00','\x00','\x00','\x00','\x00','\x00'}, //sub64 r4, 0

};

//read bytecode into buffer, set _insn_{num,avl}
ebpf_prog::ebpf_prog(FILE * fs) {

    size_t obj_size;
    size_t buf_size;
    
    size_t r_total = 0;
    size_t r_now;
    
    //get file size
    if (fseek(fs, 0, SEEK_END) == -1)
        throw std::runtime_error("ebpf_prog: fseek() to end");
    if ((obj_size = (size_t) ftell(fs)) == -1)
        throw std::runtime_error("ebpf_prog: ftell()");
    if (fseek(fs, 0, SEEK_SET) == -1)
        throw std::runtime_error("ebpf_prog: fseek() to start");


    //calculate size of buffer to allow for expansion
    buf_size = (size_t) obj_size * MAX_EXPAND;
    
    //remove mod 8 remainder from buffer size
    if (buf_size % sizeof(struct bpf_insn)) buf_size -= buf_size%sizeof(struct bpf_insn);

    //allocate file size on heap
    if ((_insn_buf = (struct bpf_insn *) std::malloc((size_t) buf_size)) == NULL)
        throw std::runtime_error("ebpf_prog: malloc()");

    //read bytecode into buffer
    while (r_total < obj_size) {

        r_now = fread(_insn_buf+r_total, sizeof(byte),
                      std::clamp(obj_size, (size_t) 0, (size_t) 4096), fs);
        //error check
        if (r_now == 0) {
            //if EOF
            if (feof(fs)) break;
            if (ferror(fs)) throw std::runtime_error("ebpf_prog: ferror()");
        }
        r_total += r_now;
    }

    //set class attributes
    _insn_num = obj_size / sizeof(struct bpf_insn);
    _insn_avl = buf_size / sizeof(struct bpf_insn);
    _insn_usd = _insn_num;

    //initialise the rng
    std::random_device rd;
    _rng = new std::mt19937(rd());
}


//check if instruction can be injected at
inline bool ebpf_prog::can_mutate_insn(struct bpf_insn * insn) {
    
    //isolate instruction class
    uint8_t opcode = insn->code & 0x07;
    //avoid CALL
    if ((opcode >= BPF_LD && opcode <= BPF_ALU) || opcode == BPF_MISC) return true;
    return false;

}


//check if instruction is a jump that operates on a relative offset
inline bool ebpf_prog::operates_on_reloff(struct bpf_insn * insn) {

    //if can_mutate_insn(), then the instruction is not a JMP/CALL
    if(this->can_mutate_insn(insn)) return false;
    //isolate instruction code
    uint8_t opcode = insn->code & 0xF0;
  
    //check if instruction is NULL (compiler my beloved) | NOTE: may not be necessary


    //check for JMP or EXIT (MISC class has many instructions)
    if ((opcode == 0x80 && insn->src_reg != 0x1) || insn->code == 0x95) return false;
    


    return true;
}


//fill injection buffer with NOP instructions
inline int ebpf_prog::fill_inject_buf(struct bpf_insn * buf, int size) {

    std::uniform_int_distribution<> insn_dist(0, NOP_LEN - 1);
    int nop_index;

    //for every instruction
    for (int i = 0; i < size; ++i) {

        nop_index = insn_dist(*_rng);
        std::memcpy(buf+i, nop_insn[nop_index], sizeof(struct bpf_insn));
    }
    return 0;
}


//patch null instructions to not exist, fixing compiler mistakes here
inline void ebpf_prog::patch_null(struct bpf_insn * insn) {

    /*NOTE: this is a hack to get around compilers outputting NULL instructions
     * this is a potential vulnerability because all NULL instructions are turned 
     * into the same NOP. the researcher lacks the time to implement this properly,
     * especially since compilers shouldn't be outputting these instructions.
     */
    bool null_check = true;
    for (int i = 0; i < sizeof(struct bpf_insn); ++i) {
        //if byte i of insn is not NULL
        if (*(((byte *) insn) + i) != 0) {null_check = false; break;}
    }

    //if NULL, set to NOP
    if (null_check) {
        insn->code = 0x07;
        insn->dst_reg = 0x03;
    }
}


//carry out the mutation
int ebpf_prog::apply_mutations() {

    //setup
    struct bpf_insn * cur_insn;

    //injection buffer
    int inject_num;
    struct bpf_insn * inject_buf;

    //gaussian distribution for injected instructions
    double tmp = (double) ((_insn_avl / _insn_num) - 1.0)
                 * (double) (INJECT_LIMIT / (INJECT_LIMIT - INJECT_THRES));
    std::normal_distribution<double> rate_dist{
        tmp,                                 //mean
        std::clamp(std::sqrt(tmp), 1.0, 8.0) //stddev
    };

    //uniform distribution for instruction spread (see config.h)
    std::uniform_real_distribution<double> inject_dist(0, INJECT_LIMIT);

    //instruction patching setup
    struct bpf_insn * fix_insn;
    struct bpf_insn * inject_end;

    //for every instruction
    for (int i = 0; i < _insn_usd; ++i) {

        cur_insn = _insn_buf + i;

        //check for null instructions, patch if necessary
        this->patch_null(cur_insn);

        //skip current instruction if it can't/shouldn't be mutated
        if (!(this->can_mutate_insn(cur_insn)) 
            || !(inject_dist(*_rng) >= INJECT_THRES)) continue;
        //bool x = this->can_mutate_insn(cur_insn);
        //double y = inject_dist(*_rng);
        //if (!x || !(y >= INJECT_THRES)) continue;
        

        //get a buffer of instructions to inject & force > 0
        inject_num = (int) std::floor(rate_dist(*_rng));
        inject_num = (inject_num <= 0) ? 1 : inject_num;

        //check for buffer overrun
        if ((_insn_usd + inject_num) >= _insn_avl) break;

        if ((inject_buf = (struct bpf_insn *) 
                          std::malloc(sizeof(struct bpf_insn) * inject_num)) == NULL)
            return -1;
        if (fill_inject_buf(inject_buf, inject_num))
            return -1;

        //inject the instructions
        std::memmove(_insn_buf+i+inject_num, _insn_buf+i, 
                     (_insn_usd - i) * sizeof(struct bpf_insn));
        std::memcpy(_insn_buf+i, inject_buf, 
                    inject_num * sizeof(struct bpf_insn));
        _insn_usd += inject_num;

        //go through instructions again
        inject_end = cur_insn - 1 + inject_num;
        for (int j = 0; j < _insn_usd; ++j) {

            fix_insn = _insn_buf + j;

            //skip if instruction doesn't need to be patched
            if (!(this->operates_on_reloff(fix_insn))) continue;

            if ((fix_insn + fix_insn->off <= inject_end) && fix_insn > inject_end)
                fix_insn->off -= inject_num;

            if ((fix_insn + fix_insn->off >= inject_end) && fix_insn < inject_end)
                fix_insn->off += inject_num;

        } //end nested for
       
        //update metainfo
        std::free(inject_buf);
        _mutate_metainf.push_back({i, inject_num});

        //update iterator to skip past injected instructions
        i += inject_num;

    } //end for every instruction 

    return 0;
}


//save mutated binary, wrapper for std::fwrite()
int ebpf_prog::save_prog(FILE * fs) {

    size_t wr = 0;
    size_t wr_total = 0;

    //write until done
    do {
        wr = std::fwrite(_insn_buf + wr_total, sizeof(struct bpf_insn), 
                         _insn_usd - wr_total, fs);
        wr_total += wr;
    } while (wr != 0 && wr_total < _insn_usd);

    //if an incorrect number of instructions was written
    if (wr_total != _insn_usd) return -1;

    return 0;
}


//save mutation meta information, allows mutations to be reversed
int ebpf_prog::save_metainf(FILE * fs) {

    //for every mutation
    for (std::vector<injection>::iterator i = _mutate_metainf.begin(); 
         i < _mutate_metainf.end(); ++i) {

        //write metainf to file & catch incomplete writes
        if (std::fwrite(&(i->index), sizeof(i->index), 1, fs) != 1)
            return -1;
        if (std::fwrite(&(i->len), sizeof(i->len), 1, fs) != 1)
            return -1;
    }
    return 0;
}




















