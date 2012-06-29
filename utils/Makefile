# ----------------------------------------------------------------------
#    Copyright (c) 1999, 2004-2009 NOVELL (All rights reserved)
#    Copyright (c) 2010-2011 Canonical Ltd.
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

MODDIR = Immunix
PERLTOOLS = aa-genprof aa-logprof aa-autodep aa-audit aa-complain aa-enforce \
	aa-unconfined aa-notify aa-disable aa-exec
TOOLS = ${PERLTOOLS} aa-decode aa-status
MODULES = ${MODDIR}/AppArmor.pm ${MODDIR}/Repository.pm \
	${MODDIR}/Config.pm ${MODDIR}/Severity.pm
PYTOOLS = aa-easyprof
PYSETUP = python-tools-setup.py

MANPAGES = ${TOOLS:=.8} logprof.conf.5 ${PYTOOLS:=.8}

all: ${MANPAGES} ${HTMLMANPAGES}
	$(MAKE) -C po all
	$(MAKE) -C vim all

# need some better way of determining this
DESTDIR=/
BINDIR=${DESTDIR}/usr/sbin
CONFDIR=${DESTDIR}/etc/apparmor
VENDOR_PERL=$(shell perl -e 'use Config; print $$Config{"vendorlib"};')
PERLDIR=${DESTDIR}${VENDOR_PERL}/${MODDIR}
PYPREFIX=/usr

po/${NAME}.pot: ${TOOLS} ${PYTOOLS}
	$(MAKE) -C po ${NAME}.pot NAME=${NAME} SOURCES="${TOOLS} ${MODULES} ${PYTOOLS}"

.PHONY: install
install: ${MANPAGES} ${HTMLMANPAGES}
	install -d ${CONFDIR}
	install -m 644 logprof.conf severity.db notify.conf ${CONFDIR}
	install -d ${BINDIR}
	ln -sf aa-status ${BINDIR}/apparmor_status
	install -m 755 ${TOOLS} ${BINDIR}
	install -d ${PERLDIR}
	install -m 644 ${MODULES} ${PERLDIR}
	$(MAKE) -C po install DESTDIR=${DESTDIR} NAME=${NAME}
	$(MAKE) install_manpages DESTDIR=${DESTDIR}
	$(MAKE) -C vim install DESTDIR=${DESTDIR}
	ln -sf aa-status.8 ${DESTDIR}/${MANDIR}/man8/apparmor_status.8
	${PYTHON} ${PYSETUP} install --prefix=${PYPREFIX} --root=${DESTDIR} --version=${VERSION}

.PHONY: clean
ifndef VERBOSE
.SILENT: clean
endif
clean: _clean
	rm -f core core.* *.o *.s *.a *~
	rm -f Make.rules
	$(MAKE) -C po clean
	$(MAKE) -C vim clean
	rm -rf staging/ build/
	rm -f apparmor/*.pyc

# ${CAPABILITIES} is defined in common/Make.rules
.PHONY: check_severity_db
.SILENT: check_severity_db
check_severity_db: /usr/include/linux/capability.h severity.db
	# The sed statement is based on the one in the parser's makefile
	RC=0 ; for cap in ${CAPABILITIES} ; do \
	    if !  grep -q -w $${cap} severity.db ; then \
		echo "Warning! capability $${cap} not found in severity.db" ; \
		RC=1 ; \
	    fi ;\
	done ; \
	test "$$RC" -eq 0

.PHONY: check
.SILENT: check
check: check_severity_db
	for i in ${MODULES} ${PERLTOOLS} ; do \
		perl -c $$i || exit 1; \
	done
	tmpfile=$$(mktemp --tmpdir aa-pyflakes-XXXXXX); \
	for i in ${PYTOOLS} apparmor aa-status test/*.py; do \
		echo Checking $$i; \
		pyflakes $$i 2>&1 | grep -v "undefined name '_'" > $$tmpfile; \
		test -s $$tmpfile && cat $$tmpfile && rm -f $$tmpfile && exit 1; \
	done || true; \
	rm -f $$tmpfile
	$(foreach test, $(wildcard test/test-*.py), $(call pyalldo, $(test)))
