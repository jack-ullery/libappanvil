INCLUDES = $(all_includes)

libaalogparsedir = $(includedir)/aalogparse

lib_LTLIBRARIES = libaalogparse.la
noinst_HEADERS = aalogparse.h grammar.h parser.h scanner.h

libaalogparse_la_SOURCES = grammar.c libaalogparse.c scanner.c 

libaalogparse_la_LDFLAGS = -module

libaalogparse_HEADERS = aalogparse.h 

EXTRA_DIST = grammar.y scanner.l   
