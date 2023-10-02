#generic makefile stuff
CC=clang
CFLAGS=-O2

#eBPF stuff
USR_EXEC=hide
USR_OBJ=hide.o
USR_SRC=hide.c

#clean
CLEAN=${USR_EXEC} ${USR_OBJ} ${BPF_SKEL} ${BPF_OBJ}
CLEAN_ALL=${CLEAN}

#build
usr: ${USR_SRC}
	gcc -ggdb -O0 -c hide.c
	gcc -ggdb -O0 -lbpf -o hide hide.o

clean:
	rm ${CLEAN}

clean_all:
	rm ${CLEAN_ALL}
