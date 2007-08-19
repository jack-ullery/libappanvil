SUBDIRS = lib config libaaprofileparse.test
PACKAGE = libaaprofileparse
AUTOMAKE_OPTIONS = dejagnu

INCLUDES = -I. -I$(top_srcdir)/src

AM_CFLAGS = $(DEBUG_FLAGS)

AM_LDFLAGS = \
	-Xlinker --whole-archive \
	$(top_builddir)/src/libaaprofileparse.la \
	-Xlinker --no-whole-archive

noinst_PROGRAMS = test_multi.multi

test_multi_multi_SOURCES	= test_multi.c
test_multi_multi_CFLAGS		= $(CFLAGS)
test_multi_multi_LDFLAGS	= $(LDFLAGS) ../src/.libs/libaaprofileparse.so

clean-local:
	rm -rf tmp.err.* tmp.out.* site.exp site.bak

EXTRA_DIST = test_multi/*.in test_multi/*.out test_multi/*.err
