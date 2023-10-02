#ifndef __TYPE_COMMON_H
#define __TYPE_COMMON_H

typedef unsigned char byte;
typedef char sbyte; //eBPF doesn't (?) run on arch's where char != int8_t
typedef struct _injection {

    int index; //instruction index of start of injection
    int len;   //length of injection in instructions

} injection;

#endif
