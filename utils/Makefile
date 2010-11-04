# 	$Id$
# ----------------------------------------------------------------------
#    Copyright (c) 1999, 2004-2009 NOVELL (All rights reserved)
#    Copyright (c) 2010 Canonical Ltd.
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
NAME 		= apparmor-utils
all:
COMMONDIR=../common/

include common/Make.rules

COMMONDIR_EXISTS=$(strip $(shell [ -d ${COMMONDIR} ] && echo true))
ifeq ($(COMMONDIR_EXISTS), true)
common/Make.rules: $(COMMONDIR)/Make.rules
	ln -sf $(COMMONDIR) .
endif

TOOLS = aa-genprof aa-logprof aa-autodep aa-audit aa-complain aa-enforce \
	aa-unconfined aa-status aa-decode aa-notify

MANPAGES = ${TOOLS:=.8} logprof.conf.5

all: ${MANPAGES} ${HTMLMANPAGES}
	make -C po all

# need some better way of determining this
DESTDIR=/
BINDIR=${DESTDIR}/usr/sbin
CONFDIR=${DESTDIR}/etc/apparmor
PERLDIR=${DESTDIR}/usr/lib/perl5/vendor_perl/Immunix

po/${NAME}.pot: ${TOOLS}
	make -C po ${NAME}.pot NAME=${NAME} SOURCES="${TOOLS} SubDomain.pm Repository.pm Config.pm Reports.pm"

.PHONY: install
install: ${MANPAGES} ${HTMLMANPAGES}
	install -d ${CONFDIR}
	install -m 644 logprof.conf severity.db notify.conf ${CONFDIR}
	install -d ${BINDIR}
	install -m 755 ${TOOLS} ${BINDIR}
	install -d ${PERLDIR}
	install -m 755 SubDomain.pm Repository.pm Config.pm Reports.pm Severity.pm ${PERLDIR}
	make -C po install DESTDIR=${DESTDIR} NAME=${NAME}
	mkdir -m 0700 -p $(DESTDIR)/var/log/apparmor
	make install_manpages DESTDIR=${DESTDIR}

.PHONY: clean
.SILENT: clean
clean: _clean
	rm -f core core.* *.o *.s *.a *~
	rm -f Make.rules
	make -C po clean

