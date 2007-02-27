# Profiling:
#EXTRA_CFLAGS = -pg

TARGET=libapparmor_re.a

CFLAGS = -c -g -Wall -O2 ${EXTRA_CFLAGS}
CXXFLAGS := ${CFLAGS}

ARFLAGS=-rcs

BISON := bison

all : ${TARGET}

libapparmor_re.a: regexp.o
	ar ${ARFLAGS} $@ $^

regexp.o : regexp.cc
	$(LINK.cc) $^ -o $@

regexp.cc : regexp.y flex-tables.h
	${BISON} -o $@ $<

clean:
	rm -f regexp{,.o,.cc,.so,.a} ${TARGET}
