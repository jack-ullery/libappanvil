# Profiling:
#EXTRA_CFLAGS = -pg

TARGET=libapparmor_re.a

CFLAGS ?= -g -Wall -O2 ${EXTRA_CFLAGS}
CXXFLAGS := ${CFLAGS}

ARFLAGS=-rcs

BISON := bison

all : ${TARGET}

libapparmor_re.a: parse.o expr-tree.o hfa.o compressed_hfa.o aare_rules.o
	ar ${ARFLAGS} $@ $^

expr-tree.o: expr-tree.cc expr-tree.h
	$(LINK.cc) $< -c -o $@

hfa.o: hfa.cc apparmor_re.h hfa.h
	$(LINK.cc) $< -c -o $@

aare_rules.o: aare_rules.cc aare_rules.h
	$(LINK.cc) $< -c -o $@

compressed_hfa.o: compressed_hfa.cc compressed_hfa.h
	$(LINK.cc) $< -c -o $@

parse.o : parse.cc apparmor_re.h expr-tree.h
	$(LINK.cc) $< -c -o $@

parse.cc : parse.y flex-tables.h ../immunix.h
	${BISON} -o $@ $<

clean:
	rm -f *.o parse.cc ${TARGET}
