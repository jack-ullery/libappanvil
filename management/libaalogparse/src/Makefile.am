INCLUDES = $(all_includes)

BUILT_SOURCES = grammar.h

AM_YFLAGS = -d -p libaalogparse_
AM_LFLAGS = 

changehatdir = $(includedir)/sys
changehat_HEADERS = apparmor.h

libaalogparsedir = $(includedir)/aalogparse

lib_LTLIBRARIES = libaalogparse.la
noinst_HEADERS = aalogparse.h grammar.h parser.h scanner.h apparmor.h

libaalogparse_la_SOURCES = scanner.l grammar.y libaalogparse.c change_hat.c libimmunix_warning.c

libaalogparse_la_LDFLAGS = -module

libaalogparse_HEADERS = aalogparse.h



EXTRA_DIST = grammar.y scanner.l   
