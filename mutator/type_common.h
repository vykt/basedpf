#ifndef __TYPE_COMMON_H
#define __TYPE_COMMON_H

#include <cstdint>

typedef uint8_t byte;
typedef struct _injection {

    int index; //instruction index of start of injection
    int len;   //length of injection in instructions

} injection;

#endif
