# 	$Id$
# ----------------------------------------------------------------------
#    Copyright (c) 2004, 2005, 2006 NOVELL (All rights reserved)
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, contact Novell, Inc.
# ----------------------------------------------------------------------
NAME=apparmor-parser
all:
COMMONDIR=../common/

include common/Make.rules

COMMONDIR_EXISTS=$(strip $(shell [ -d ${COMMONDIR} ] && echo true))
ifeq ($(COMMONDIR_EXISTS), true)
common/Make.rules: $(COMMONDIR)/Make.rules
	ln -sf $(COMMONDIR) .
endif

DESTDIR=/
APPARMOR_BIN_PREFIX=${DESTDIR}/lib/apparmor
CONFDIR=/etc/apparmor
INSTALL_CONFDIR=${DESTDIR}${CONFDIR}
LOCALEDIR=/usr/share/locale

YACC	:= /usr/bin/bison
YFLAGS	:= -d
LEX	:= /usr/bin/flex
LEXFLAGS = -B -v
WARNINGS = -Wall -Wstrict-prototypes
EXTRA_WARNINGS = -Wsign-compare -Wmissing-field-initializers -Wnested-externs -Wformat-security -Wunused-parameter
WARNINGS += $(shell for warning in ${EXTRA_WARNINGS} ; do \
			if ${CC} $${warning} -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then \
				echo "$${warning}"; \
			fi ; \
		done)
CFLAGS	= -O2 -pipe

ifdef DEBUG
CFLAGS = -g
endif
EXTRA_CFLAGS = ${CFLAGS} ${WARNINGS}

#LEXLIB	:= -lfl

# override this on the make command to point to where the immunix.h file is
# (yeah this is lame, but since we are tied to the kernel so tightly...)
#INCLUDEDIR = /usr/src/linux/include
INCLUDEDIR =

ifdef INCLUDEDIR
	CFLAGS += -I$(INCLUDEDIR)
endif

EXTRA_CFLAGS+=$(shell [ -e /usr/include/sys/capability.h ] || echo -DNOLIBCAP)

# Internationalization support. Define a package and a LOCALEDIR
EXTRA_CFLAGS+=-DPACKAGE=\"${NAME}\" -DLOCALEDIR=\"${LOCALEDIR}\"

# Compile-time configuration of the location of the config file
EXTRA_CFLAGS+=-DSUBDOMAIN_CONFDIR=\"${CONFDIR}\"

SRCS = parser_include.c parser_interface.c parser_lex.c parser_main.c \
       parser_misc.c parser_merge.c parser_symtab.c parser_yacc.c \
       parser_regex.c parser_variable.c parser_policy.c
HDRS = parser.h parser_include.h immunix.h
TOOLS = apparmor_parser

OBJECTS = parser_lex.o parser_yacc.o parser_main.o parser_interface.o \
	  parser_include.o parser_merge.o parser_symtab.o parser_misc.o \
	  parser_regex.o parser_variable.o parser_policy.o

PCREDIR= pcre
PCREOBJECTS = ${PCREDIR}/pcre.o

LEX_C_FILES	= parser_lex.c
YACC_C_FILES	= parser_yacc.c parser_yacc.h

TESTS = tst_regex tst_misc tst_symtab tst_variable
TEST_FLAGS = -Wl,--warn-unresolved-symbols
DISABLED_TESTS =

TEST_OBJECTS = $(filter-out parser_lex.o, \
	       $(filter-out parser_yacc.o, \
	       $(filter-out parser_main.o, ${OBJECTS} ${PCREOBJECTS})))

ifndef VERBOSE
  VERBOSE = 0
endif
ifeq ($(VERBOSE),1)
  BUILD_OUTPUT =
  Q =
else
  BUILD_OUTPUT = > /dev/null 2>&1
  Q = @
endif
export Q VERBOSE BUILD_OUTPUT

po/${NAME}.pot: ${SRCS} ${HDRS}
	make -C po ${NAME}.pot NAME=${NAME} SOURCES="${SRCS} ${HDRS}"

all: 	$(LEX_C_FILES) $(YACC_C_FILES) $(TOOLS)
	$(Q)make -C po all
	$(Q)make -s tests

apparmor_parser: $(OBJECTS) $(PCREOBJECTS)
	$(CC) $(EXTRA_CFLAGS) -o $@ $(OBJECTS) $(PCREOBJECTS) $(LIBS) ${LEXLIB}

parser_yacc.c parser_yacc.h: parser_yacc.y parser.h
	$(YACC) $(YFLAGS) -o parser_yacc.c parser_yacc.y 

parser_lex.c: parser_lex.l parser_yacc.h parser.h
	$(LEX) ${LEXFLAGS} -o$@ $<

parser_lex.o: parser_lex.c parser.h parser_yacc.h
	$(CC) $(EXTRA_CFLAGS) -c -o $@ $<

parser_misc.o: parser_misc.c parser.h parser_yacc.h
	$(CC) $(EXTRA_CFLAGS) -c -o $@ $<

parser_yacc.o: parser_yacc.c parser_yacc.h
	$(CC) $(EXTRA_CFLAGS) -c -o $@ $<

parser_main.o: parser_main.c parser.h parser_version.h
	$(CC) $(EXTRA_CFLAGS) -c -o $@ $<

parser_interface.o: parser_interface.c parser.h
	$(CC) $(EXTRA_CFLAGS) -c -o $@ $<

parser_include.o: parser_include.c parser.h parser_include.h
	$(CC) $(EXTRA_CFLAGS) -c -o $@ $<

parser_merge.o: parser_merge.c parser.h
	$(CC) $(EXTRA_CFLAGS) -c -o $@ $<

parser_regex.o: parser_regex.c parser.h
	$(CC) $(EXTRA_CFLAGS) -c -o $@ $<

parser_symtab.o: parser_symtab.c parser.h
	$(CC) $(EXTRA_CFLAGS) -c -o $@ $<

parser_variable.o: parser_variable.c parser.h
	$(CC) $(EXTRA_CFLAGS) -c -o $@ $<

parser_policy.o: parser_policy.c parser.h parser_yacc.h
	$(CC) $(EXTRA_CFLAGS) -c -o $@ $<

parser_version.h: Makefile
	@echo \#define PARSER_VERSION \"$(VERSION)\" > .ver
	@mv -f .ver $@

tst_symtab: parser_symtab.c parser.h parser_variable.o
	$(Q)$(CC) -DUNIT_TEST $(EXTRA_CFLAGS) $(TEST_FLAGS) -o $@ $< parser_variable.o $(BUILD_OUTPUT)

tst_variable: parser_variable.c parser.h $(filter-out parser_variable.o, ${TEST_OBJECTS})
	$(Q)$(CC) -DUNIT_TEST $(EXTRA_CFLAGS) $(TEST_FLAGS) -o $@ $< $(filter-out parser_variable.o, ${TEST_OBJECTS}) $(BUILD_OUTPUT)

tst_misc: parser_misc.c parser.h parser_yacc.h
	$(Q)$(CC) -DUNIT_TEST $(EXTRA_CFLAGS) $(TEST_FLAGS) -o $@ $< $(BUILD_OUTPUT)

tst_regex: parser_regex.c parser.h parser_yacc.h $(PCREOBJECTS)
	$(Q)$(CC) -DUNIT_TEST $(EXTRA_CFLAGS) $(TEST_FLAGS) -o $@ $< $(PCREOBJECTS) $(BUILD_OUTPUT)

.SILENT: tests
tests: ${TESTS}
	for test in ${TESTS} ; do echo "*** running $${test}" && ./$${test} $(BUILD_OUTPUT) ; done
	$(Q)make -s -C tst tests

# always need to rebuild.
.SILENT: $(PCREOBJECTS)
$(PCREOBJECTS):
	make -C $(PCREDIR) "CFLAGS=$(CFLAGS)"

.PHONY: install-rhel4
install-rhel4: install-redhat

.PHONY: install-redhat
install-redhat:
	install -m 755 -d $(DESTDIR)/etc/init.d
	install -m 755 rc.apparmor.$(subst install-,,$@) $(DESTDIR)/etc/init.d/apparmor

.PHONY: install-suse
install-suse:
	install -m 755 -d $(DESTDIR)/etc/init.d
	install -m 755 rc.apparmor.$(subst install-,,$(@)) $(DESTDIR)/etc/init.d/boot.apparmor
	install -m 755 rc.aaeventd.$(subst install-,,$(@)) $(DESTDIR)/etc/init.d/aaeventd
	install -m 755 -d $(DESTDIR)/sbin
	ln -sf /etc/init.d/boot.apparmor $(DESTDIR)/sbin/rcapparmor
	ln -sf rcapparmor $(DESTDIR)/sbin/rcsubdomain
	ln -sf /etc/init.d/aaeventd $(DESTDIR)/sbin/rcaaeventd
	
.PHONY: install-slackware
install-slackware:
	install -m 755 -d $(APPARMOR_BIN_PREFIX)/install
	install -m 755 frob_slack_rc $(APPARMOR_BIN_PREFIX)/install
	install -m 755 -d $(DESTDIR)/etc/rc.d
	install -m 755 rc.apparmor.$(subst install-,,$(@)) $(DESTDIR)/etc/rc.d/rc.apparmor

INSTALLDEPS=$(TOOLS)
ifdef DISTRO
INSTALLDEPS+=install-$(DISTRO)
endif

.PHONY: install
install: $(INSTALLDEPS)
	install -m 755 -d $(DESTDIR)/sbin
	install -m 755 ${TOOLS} $(DESTDIR)/sbin
	install -m 755 -d $(INSTALL_CONFDIR)
	install -m 644 subdomain.conf $(INSTALL_CONFDIR)
	install -m 755 -d ${DESTDIR}/var/lib/apparmor
	install -m 755 -d $(APPARMOR_BIN_PREFIX)
	install -m 755 rc.apparmor.functions $(APPARMOR_BIN_PREFIX)
	make -C po install NAME=${NAME} DESTDIR=${DESTDIR}

.SILENT: clean
.PHONY: clean
clean:
	rm -f core core.* *.o *.s *.a *~ 
	rm -f $(TOOLS) $(TESTS)
	rm -f $(LEX_C_FILES)
	rm -f $(YACC_C_FILES)
	rm -f parser_version.h
	rm -f $(NAME)*.tar.gz $(NAME)*.tgz
	make -s -C $(PCREDIR) clean
	make -s -C po clean

.SILENT: dist_clean
dist_clean:
	@make clean
	@rm -f $(LEX_C_FILES) $(YACC_C_FILES)
