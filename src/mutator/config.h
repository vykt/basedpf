#ifndef CONFIG_H
#define CONFIG_H

#include <linux/bpf.h>

#include "type_common.h"

//size of bytecode after mutation can be MAX_EXPAND times as big as the original
#define MAX_EXPAND 2.0f
//probability ebpf_prog::can_mutate() returns true, works as following: 
//(random int x % INJECT_LIMIT) must be >= INJECT_THRES for an injection to proceed
#define INJECT_THRES 4.0f 
#define INJECT_LIMIT 10.0f

//number of NOP instructions available
//#define NOP_LEN 3


/*sbyte nop_insn[NOP_LEN][sizeof(struct bpf_insn)] {
    {'\x07','\x03','\x00','\x00','\x00','\x00','\x00','\x00'}, //add64 r3, 0
    {'\xbf','\x22','\x00','\x00','\x00','\x00','\x00','\x00'}, //mov64 r2, r2
    {'\x17','\x04','\x00','\x00','\x00','\x00','\x00','\x00'}, //sub64 r4, 0

};*/


#endif
