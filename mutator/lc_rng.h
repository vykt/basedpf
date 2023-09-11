#ifndef __LC_RNG_H
#define __LC_RNG_H

#include <cstdint> //need precise ints

#include "type_common.h"
#include "config.h"


class rng {

    private:
    #ifndef ARCH64
        //attributes
        uint64_t _seed;
        uint64_t _mlt;
        uint64_t _inc;
        uint64_t _mod;

    #else        
        //attributes
        uint32_t _seed;
        uint32_t _mlt;
        uint32_t _inc;
        uint32_t _mod;

    #endif

    public:

        //methods
        rng();
        inline int get_num(int lim = 0); 
};

#endif
