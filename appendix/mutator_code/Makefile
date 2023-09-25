CXX=g++
CXX_FLAGS=-std=c++17 -O0 -ggdb

SOURCES=mutate.cpp main.cpp lc_rng.cpp
HEADERS=config.h type_common.h mutate.h lc_rng.h
OBJECTS=${SOURCES:.c=.o}

TARGET=mutator
CLEAN_TARGET=mutator


${TARGET} : ${OBJECTS}
	${CXX} ${CXX_FLAGS} -o ${TARGET} ${OBJECTS} ${HEADERS}

%.o: %.cpp ${HEADERS}
	${CXX} ${CXX_FLAGS} -c $< -o $@

clean:
	rm ${CLEAN_TARGET}
