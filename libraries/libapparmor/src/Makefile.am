INCLUDES = $(all_includes)

# variables to set the library versions used by libtool
# Use these rules to update the library version.
# 1. Update the version information only immediately before a public release
#    of your software. More frequent updates are unnecessary, and only
#    guarantee that the current interface number gets larger faster.
# 2. If the library source code has changed at all since the last update,
#    then
#    - increment AA_LIB_REVISION
# 3. If any interfaces have been added, removed, or changed since the last
#    update,
#    - increment AA_LIB_CURRENT
#    - set AA_LIB_REVISION to 0.
# 4. If any interfaces have been added since the last public release, then
#    - increment AA_LIB_AGE.
# 5. If any interfaces have been removed or changed since the last public
#    release, then
#    - set AA_LIB_AGE to 0.
#
AA_LIB_CURRENT = 1
AA_LIB_REVISION = 2
AA_LIB_AGE = 0

SUFFIXES = .pc.in .pc

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
libapparmor_la_LDFLAGS = -version-info $(AA_LIB_CURRENT):$(AA_LIB_REVISION):$(AA_LIB_AGE) -XCClinker -dynamic \
	-Wl,--version-script=$(top_srcdir)/src/libapparmor.map -Wl,-soname=libapparmor.so.1

libimmunix_la_SOURCES = kernel_interface.c libimmunix_warning.c
libimmunix_la_LDFLAGS = -version-info $(AA_LIB_CURRENT):$(AA_LIB_REVISION):$(AA_LIB_AGE) -Wl,--version-script=$(top_srcdir)/src/libapparmor.map -Wl,-soname=libimmunix.so.1

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libapparmor.pc

CLEANFILES = libapparmor.pc

%.pc: %.pc.in $(top_builddir)/config.status
	$(AM_V_GEN)cd "$(top_builddir)" && \
	$(SHELL) ./config.status --file="src/$@"

tst_aalogmisc_SOURCES = tst_aalogmisc.c
tst_aalogmisc_LDADD = .libs/libapparmor.a
check_PROGRAMS = tst_aalogmisc
TESTS = $(check_PROGRAMS)

EXTRA_DIST = grammar.y scanner.l libapparmor.map libapparmor.pc
