#include <cstdio>

#include "config.h"
#include "type_common.h"
#include "mutate.h"


int main() {

    //constants
    const char * mutate_target = "./prog.bpf.o";
    const char * output_target = "./prog.new.bpf.o";
    const char * metainf_target = "./prog.new.metainf";

    //open the target bpf program
    FILE * fs = std::fopen(mutate_target, "rb");
    if (!fs) {
        perror("fopen in");
        return -1;
    }

    //instantiate bpf_prog
    ebpf_prog test_prog(fs);
    std::fclose(fs);

    //mutate the bpf program
    if (test_prog.apply_mutations()) {
        fprintf(stderr, "apply_mutations() fail.\n");
        return -1;
    }

    //save the mutated program
    fs = std::fopen(output_target, "wb");
    if (!fs) {
        perror("fopen out bin");
        return -1;
    }

    if (test_prog.save_prog(fs)) {
        fprintf(stderr, "save_prog() fail.\n");
        return -1;
    }
    std::fclose(fs);

    //save metainf for the mutated program
    fs = std::fopen(metainf_target, "wb");
    if (!fs) {
        perror("fopen out meta");
        return -1;
    }

    if (test_prog.save_metainf(fs)) {
        fprintf(stderr, "save_metainf() fail.\n");
        return -1;
    }
    fclose(fs);

    return 0;
}
