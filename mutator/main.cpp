#include <cstdio>

#include "config.h"
#include "type_common.h"
#include "mutate.h"


int main() {

    //open the target bpf program
    FILE * fs = std::fopen("hide.bpf.o", "rb");
    if (!fs) {
        perror("fopen in");
        return -1;
    }

    //instantiate bpf_prog
    bpf_prog hide_prog(fs);
    std::fclose(fs);

    //mutate the bpf program
    if (apply_mutations()) {
        fprintf(stderr, "apply_mutations() fail.\n");
        return -1;
    }

    //save the mutated program
    fs = std::fopen("mutated.bpf.o", "wb");
    if (!fs) {
        perror("fopen out bin");
        return -1;
    }

    if (bpf::save_prog(fs)) {
        fprintf(stderr, "save_prog() fail.\n");
        return -1;
    }


    //save metainf for the mutated program
    fs = std::fopen("hide.metainf.bin", "wb");
    if (!fs) {
        perror("fopen out meta");
        return -1;
    }

    if (save_metainf(fs)) {
        fprintf(stderr, "save_metainf() fail.\n");
        return -1;
    }
    fclose(fs);

    return 0;
}
