INCLUDES = $(all_includes)

BUILT_SOURCES = grammar.h scanner.h
AM_LFLAGS = -v
AM_YFLAGS = -d -p aalogparse_
AM_CFLAGS = @CFLAGS@ -D_GNU_SOURCE -Wall
scanner.h: scanner.l
	$(LEX) -v $<

scanner.c: scanner.l

changehatdir = $(includedir)/sys
changehat_HEADERS = apparmor.h

aalogparsedir = $(includedir)/aalogparse
aalogparse_HEADERS = aalogparse.h

lib_LTLIBRARIES = libapparmor.la libimmunix.la
noinst_HEADERS = grammar.h parser.h scanner.h

libapparmor_la_SOURCES = grammar.y libaalogparse.c change_hat.c scanner.c
libapparmor_la_LDFLAGS = -version-info 1:2:0 -XCClinker -dynamic \
	-Wl,--version-script=libapparmor.map -Wl,-soname=libapparmor.so.1

libimmunix_la_SOURCES = change_hat.c libimmunix_warning.c
libimmunix_la_LDFLAGS = -version-info 1:2:0 -Wl,--version-script=libapparmor.map -Wl,-soname=libimmunix.so.1

tst_aalogmisc_SOURCES = tst_aalogmisc.c
tst_aalogmisc_LDADD = .libs/libapparmor.a
check_PROGRAMS = tst_aalogmisc
TESTS = $(check_PROGRAMS)

EXTRA_DIST = grammar.y scanner.l libapparmor.map
