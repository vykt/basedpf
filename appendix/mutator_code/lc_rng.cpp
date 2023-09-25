#include <cstdlib>
#include <cstdint>
#include <climits>

#include <unistd.h>
#include <fcntl.h>

#include <stdexcept>

#include "lc_rng.h"
#include "type_common.h"
#include "config.h"


rng::rng() {

    //fill attributes
    #ifndef ARCH64
    size_t to_read = 8;
    _mod = UINT64_MAX;
    _mlt = 6364136223846793005;
    _inc = 1442695040888963407;
    
    #else
    size_t to_read = 4;
    _mod = UINT32_MAX;
    _mlt = 1664525;
    _inc = 1013904223;

    #endif

    //get random seed (may block) 
    int fd;
    if ((fd = open("/dev/random", O_RDONLY)) == -1)
        throw std::runtime_error("lc_rng: open()");

    if (read(fd, &_seed, to_read) != (ssize_t) to_read)
        throw std::runtime_error("lc_rng: read()");
    close(fd);
}


inline int rng::get_num(int lim) {

    _seed = (_mlt * _seed + _inc) % _mod;
    if (lim) return (int) abs(_seed % lim);
    return (int) abs(_seed);
}
