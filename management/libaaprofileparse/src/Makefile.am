INCLUDES = $(all_includes) -I./antlr -I/usr/include

libaaprofileparsedir = $(includedir)/aaprofileparse

lib_LTLIBRARIES = libaaprofileparse.la

noinst_headers = AppArmorLexer.h  AppArmorParser.h  DataNodes.h  libaaprofileparse.h  Nodes.h  ParseNode.h  Types.h Exceptions.h

libaaprofileparse_la_SOURCES = AppArmorLexer.c AppArmorParser.c  DataNodes.c  ParseNode.c libaaprofileparse.c

libaaprofileparse_la_LDFLAGS = -module

libaaprofileparse_HEADERS = DataNodes.h libaaprofileparse.h  Nodes.h ParseNode.h Types.h

libaaprofileparse_la_LIBADD = $(top_builddir)/src/antlr/libantlr3c.la
SUBDIRS = antlr

EXTRA_DIST = AppArmor.g
