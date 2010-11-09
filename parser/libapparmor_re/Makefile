# Profiling:
#EXTRA_CFLAGS = -pg

TARGET=libapparmor_re.a

CFLAGS = -g -Wall -O2 ${EXTRA_CFLAGS}
CXXFLAGS := ${CFLAGS}

ARFLAGS=-rcs

BISON := bison

all : ${TARGET}

libapparmor_re.a: regexp.o
	ar ${ARFLAGS} $@ $^

regexp.o : regexp.cc apparmor_re.h
	$(LINK.cc) $< -c -o $@

regexp.cc : regexp.y flex-tables.h
	${BISON} -o $@ $<

clean:
	rm -f regexp.o regexp.cc regexp.so regexp.a regexp ${TARGET}
