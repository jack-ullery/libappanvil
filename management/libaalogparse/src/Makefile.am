INCLUDES = $(all_includes)

BUILT_SOURCES = grammar.h

AM_YFLAGS = -d -p libaalogparse_
AM_LFLAGS = 

libaalogparsedir = $(includedir)/aalogparse

lib_LTLIBRARIES = libaalogparse.la
noinst_HEADERS = aalogparse.h grammar.h parser.h scanner.h

libaalogparse_la_SOURCES = scanner.l grammar.y libaalogparse.c

libaalogparse_la_LDFLAGS = -module

libaalogparse_HEADERS = aalogparse.h 

EXTRA_DIST = grammar.y scanner.l   
