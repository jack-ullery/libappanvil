# ------------------------------------------------------------------
#
#    $Id$
#
#    Copyright (C) 2002-2006 Novell/SUSE
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
#
# ------------------------------------------------------------------

# Makefile for LSM-based AppArmor SuSE profiles

NAME=apparmor-profiles
ALL:
COMMONDIR=../common/

include common/Make.rules

COMMONDIR_EXISTS=$(strip $(shell [ -d ${COMMONDIR} ] && echo true))
ifeq ($(COMMONDIR_EXISTS), true)
common/Make.rules: $(COMMONDIR)/Make.rules
	ln -sf $(COMMONDIR) .
endif

DESTDIR=/
EXTRASDIR=${DESTDIR}/usr/src/immunix/SubDomain/profiles/extras

.PHONY: install
install: 
	install -d ${DESTDIR}/etc/apparmor.d
	install -m 644 enabled/* ${DESTDIR}/etc/apparmor.d
	install -d ${EXTRASDIR}
	install -m 644 extras/* ${EXTRASDIR}
	install -m 755 -d ${DESTDIR}/etc/apparmor.d/abstractions \
                   ${DESTDIR}/etc/apparmor.d/program-chunks \
                   ${DESTDIR}/etc/apparmor.d/tunables
	install -m 644 abstractions/* ${DESTDIR}/etc/apparmor.d/abstractions
	install -m 644 program-chunks/* ${DESTDIR}/etc/apparmor.d/program-chunks
	install -m 644 tunables/* ${DESTDIR}/etc/apparmor.d/tunables


.PHONY: clean
clean:
	-rm -f $(NAME)-$(VERSION)*.tar.gz Make.rules

ifndef VERBOSE
  Q=@
else
  Q=
endif

ifndef PARSER
# use system parser
PARSER=/sbin/apparmor_parser
endif

ifndef LOGPROF
# use system logprof
LOGPROF=/usr/sbin/aa-logprof
endif

ENABLED_PATH=./enabled
EXTRAS_PATH=./extras
IGNORE_FILES=${EXTRAS_PATH}/README
CHECK_PROFILES=$(filter-out ${IGNORE_FILES}, $(wildcard ${ENABLED_PATH}/*) $(wildcard ${EXTRAS_PATH}/*))
CHECK_INCLUDES=${PWD}

.PHONY: check
check:
	@echo "*** Checking profiles against apparmor_parser"
	$(Q)for profile in ${CHECK_PROFILES} ; do \
		${PARSER} -S -b ${CHECK_INCLUDES} $${profile} > /dev/null ; \
	done

.PHONY: check-install
check-install:
	$(Q)make check ENABLED_PATH=${DESTDIR}/etc/apparmor.d EXTRAS_PATH=${EXTRASDIR} CHECK_INCLUDES=${DESTDIR}/etc/apparmor.d
	@echo "*** Checking profiles against logprof"
	$(Q)${LOGPROF} -d ${DESTDIR}/etc/apparmor.d -f /dev/null
