INCLUDES = $(all_includes)

BUILT_SOURCES = grammar.h scanner.h
AM_YFLAGS = -d -p libaalogparse_

scanner.h:
	$(LEX) scanner.l

libaalogparsedir = $(includedir)/aalogparse

lib_LTLIBRARIES = libaalogparse.la
noinst_HEADERS = aalogparse.h grammar.h parser.h scanner.h

libaalogparse_la_SOURCES = grammar.y libaalogparse.c lex.yy.c

libaalogparse_la_LDFLAGS = -module

libaalogparse_HEADERS = aalogparse.h

EXTRA_DIST = grammar.y scanner.l   
