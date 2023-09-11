#include <cstdio>
#include <cstdlib>
#include <cunistd>
#include <cstring>
#include <cmath>

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <vector>
#include <exception>
#include <algorithm>
#include <random>

#include "mutate.h"
#include "type_common.h"
#include "config.h"


extern nop_insn[NOP_LEN][sizeof(struct bpf_insn)];

//read bytecode into buffer, set _insn_{num,avl}
ebpf_prog::ebpf_prog(FILE * fs) {

    size_t obj_size;
    size_t buf_size;
    
    size_t r_total = 0;
    size_t r_now;

    _fs = fs;
    
    //get file size
    if (fseek(_fs, 0, SEEK_END) == -1)
        throw std::runtime_error("ebpf_prog: fseek()");
    if ((obj_size = (size_t) ftell(_fs)) == -1)
        throw std::runtime_error("ebpf_prog: ftell()");
    
    //calculate size of buffer to allow for expansion
    buf_size = (size_t) obj_size * MAX_EXPAND;
    if (buf_size % sizeof(struct bpf_insn) buf_size -= buf_size%sizeof(struct bpf_insn);

    //allocate file size on heap
    if ((_insn_buf = malloc((size_t) buf_size)) == NULL)
        throw std::runtime_error("ebpf_prog: malloc()");

    //read bytecode into buffer
    while (r_total < obj_size) {
        r_now = fread(_insn_buf+r_total, sizeof(byte), 
                      std::clamp(obj_size, 0, 4096), _fs);
        //error check
        if (r_now == 0) {
            //if EOF
            if (feof(_fs)) break;
            if (ferror(_fs)) throw std::runtime_error("ebpf_prog: ferror()");
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
inline bool ebpf_prog::can_mutate_insn(struct ebpf_insn * insn) {
    
    //isolate instruction class
    uint8_t opcode = insn->code & 0x07;
    //if not JMP or CALL
    if ((opcode >= BPF_LDX && opcode <= BPF_ALU) || opcode == BPF_MISC) return true;
    return false;

}


//check if instruction is a jump that operates on a relative offset
inline bool ebpf_prog::operates_on_reloff(struct bpf_insn * insn) {

    //if can_mutate_insn(), then the instruction is not a JMP/CALL
    if(this->can_mutate_insn(insn)) return false;
    //isolate instruction code
    uint8_t opcode = insn->code & 0xF0;
    //do not mutate helper calls & BTF calls
    if (opcode == 0x8 && insn->src_reg != 0x1) return false;
    return true;
}


//fill injection buffer with NOP instructions
inline int ebpf_prog::fill_inject_buf(struct bpf_insn * buf, int size) {

    std::uniform_int_distribution<> insn_dist(0, NOP_LEN);
    int nop_index;

    //for every instruction
    for (int i = 0; i < size; ++i) {

        nop_index = insn_dist(_rng);
        std::memcpy(buf+(i * sizeof(struct bpf_insn)), 
                    nop_insn[nop_index], sizeof(struct bpf_insn));
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
    double tmp = (double) (_insn_avl / _insn_num) - 1;
    std::normal_distribution<double> rate_dist{
        tmp,                                 //mean
        std::clamp(std::sqrt(tmp), 1.0, 8.0) //stddev
    };

    //instruction patching setup
    struct bpf_insn * fix_insn;
    struct bpf_insn * inject_end;

    //for every instruction
    for (int i = 0; i < _insn_usd; ++i) {

        cur_insn = _insn_buf + i;

        //skip current instruction if it can't/shouldn't be mutated
        if (!(this->can_mutate_insn(cur_insn)) 
            || !(_rng.get_num(INJECT_LIMIT) >= INJECT_THRES)) continue;

        //get a buffer of instructions to inject & check for buffer overrun
        inject_num = (int) std::floor(rate_dist(_rng));
        
        if ((_insn_usd + inject_num) >= _insn_avl) break;

        if ((inject_buf = std::malloc(sizeof(struct bpf_insn) * inject_num)) == NULL)
            return -1;
        if (fill_inject_buf(inject_buf, inject_num))
            return -1;

        //inject the instructions
        std::memmove(_insn_buf+i+inject_num, _insn_buf+i, _insn_usd - i);
        std::memcpy(_insn_buf+i, inject_buf, inject_num);
        _insn_usd += inject_num;

        //go through instructions again
        inject_end = cur_insn - 1 + inject_num;
        for (int j = 0; i < _insn_usd; ++j) {

            fix_insn = _insn_buf + j;

            //skip if instruction doesn't need to be patched
            if (!(this->operates_on_reloff(fix_insn))) continue;

            if ((fix_insn + fix_insn->off <= inject_end) && fix_insn > inject_end)
                fix_insn->off -= inject_num;

            if ((fix_insn + fix_insn->off >= inject_end) && fix_insn < inject_end)
                fix_insn->off += inject_num;

        } //end nested for
        
        std::free(inject_buf);
        _mutate_metainf.push_back({i, inject_num});

    } //end for every instruction 

    return 0;
}


//save mutated binary, wrapper for std::fwrite()
int bpf::save_prog(FILE * fs) {

    size_t wr = 0;
    
    //write until done
    do {
        wr = std::fwrite(_insn_buf + i, sizeof(struct bpf_insn), _insn_usd - wr, fs);
    } while (wr != 0);
}


//save mutation meta information, allows mutations to be reversed
int bpf_prog::save_metainf(FILE * fs) {

    //for every mutation
    for (std::vector<injection>::iterator i = _mutate_metainf.begin(); 
         i != _mutate_metainf.end(); ++i) {

        //write metainf to file & catch incomplete writes
        if (std::fwrite(&(i->index), sizeof(i->index), 1, fs) != sizeof(i->index))
            return -1;
        if (std::fwrite(&(i->index), sizeof(i->index), 1, fs) != sizeof(i->index))
            return -1;
    }
    return 0;
}




















