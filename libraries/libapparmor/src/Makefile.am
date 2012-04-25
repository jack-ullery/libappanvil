INCLUDES = $(all_includes)

BUILT_SOURCES = grammar.h scanner.h af_protos.h
AM_LFLAGS = -v
AM_YFLAGS = -d -p aalogparse_
AM_CFLAGS = -Wall
AM_CPPFLAGS = -D_GNU_SOURCE
scanner.h: scanner.l
	$(LEX) -v $<

scanner.c: scanner.l

af_protos.h: /usr/include/netinet/in.h
	 LC_ALL=C  sed  -n -e "/IPPROTO_MAX/d"  -e "s/^\#define[ \\t]\\+IPPROTO_\\([A-Z0-9_]\\+\\)\\(.*\\)$$/AA_GEN_PROTO_ENT(\\UIPPROTO_\\1, \"\\L\\1\")/p" $< > $@

changehatdir = $(includedir)/sys
changehat_HEADERS = apparmor.h

aalogparsedir = $(includedir)/aalogparse
aalogparse_HEADERS = aalogparse.h

lib_LTLIBRARIES = libapparmor.la libimmunix.la
noinst_HEADERS = grammar.h parser.h scanner.h af_protos.h

libapparmor_la_SOURCES = grammar.y libaalogparse.c kernel_interface.c scanner.c
libapparmor_la_LDFLAGS = -version-info 1:2:0 -XCClinker -dynamic \
	-Wl,--version-script=$(top_srcdir)/src/libapparmor.map -Wl,-soname=libapparmor.so.1

libimmunix_la_SOURCES = kernel_interface.c libimmunix_warning.c
libimmunix_la_LDFLAGS = -version-info 1:2:0 -Wl,--version-script=$(top_srcdir)/src/libapparmor.map -Wl,-soname=libimmunix.so.1

tst_aalogmisc_SOURCES = tst_aalogmisc.c
tst_aalogmisc_LDADD = .libs/libapparmor.a
check_PROGRAMS = tst_aalogmisc
TESTS = $(check_PROGRAMS)

EXTRA_DIST = grammar.y scanner.l libapparmor.map
