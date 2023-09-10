#generic makefile stuff
CC=clang
CFLAGS=-O2

#eBPF stuff
USR_EXEC=hide
USR_OBJ=hide.o
USR_SRC=hide.c

#BPF_SKEL=hide.skel.h

BPF_OBJ=hide.bpf.o
BPF_SRC=hide.bpf.c

#clean
CLEAN=${USR_EXEC} ${USR_OBJ} ${BPF_SKEL} ${BPF_OBJ}
CLEAN_ALL=${CLEAN} vmlinux.h

#build
usr: ${USR_SRC}
	gcc -ggdb -O0 -c hide.c
	gcc -ggdb -O0 -lbpf -o hide hide.o

bpf: ${BPF_SRC}
	${CC} ${CFLAGS} -fno-stack-protector -target bpf -D__TARGET_ARCH_x86_64 -c hide.bpf.c -o hide.bpf.o

init:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm ${CLEAN}

clean_all:
	rm ${CLEAN_ALL}
