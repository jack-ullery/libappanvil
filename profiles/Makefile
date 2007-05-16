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
PROFILES_DEST=${DESTDIR}/etc/apparmor.d
EXTRAS_DEST=${DESTDIR}/etc/apparmor/profiles/extras/
PROFILES_SOURCE=./apparmor.d
EXTRAS_SOURCE=./apparmor/profiles/extras/
SUBDIRS_MUST_BE_SKIPPED=${PROFILES_SOURCE}/abstractions ${PROFILES_SOURCE}/program-chunks ${PROFILES_SOURCE}/tunables
PROFILES_TO_COPY=$(filter-out ${SUBDIRS_MUST_BE_SKIPPED}, $(wildcard ${PROFILES_SOURCE}/*))

.PHONY: install
install: 
	install -m 755 -d ${PROFILES_DEST}
	install -m 755 -d ${PROFILES_DEST}/abstractions \
                          ${PROFILES_DEST}/program-chunks \
                          ${PROFILES_DEST}/tunables
	install -m 644 ${PROFILES_TO_COPY} ${PROFILES_DEST}
	install -m 644 ${PROFILES_SOURCE}/abstractions/* ${PROFILES_DEST}/abstractions
	install -m 644 ${PROFILES_SOURCE}/program-chunks/* ${PROFILES_DEST}/program-chunks
	install -m 644 ${PROFILES_SOURCE}/tunables/* ${PROFILES_DEST}/tunables
	install -m 755 -d ${EXTRAS_DEST}
	install -m 644 ${EXTRAS_SOURCE}/* ${EXTRAS_DEST}

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

EXTRAS_PATH=${EXTRAS_SOURCE}/profiles/extras
IGNORE_FILES=${EXTRAS_PATH}/README
CHECK_PROFILES=$(filter-out ${IGNORE_FILES}, $(wildcard ${PROFILES_SOURCE}/*) $(wildcard ${EXTRAS_PATH}/*))

.PHONY: check
check:
	@echo "*** Checking profiles from ${PROFILES_SOURCE} and ${EXTRAS_PATH} against apparmor_parser"
	$(Q)for profile in ${CHECK_PROFILES} ; do \
		${PARSER} -S -I ${PWD}/apparmor.d $${profile} > /dev/null ; \
	done
	@echo "*** Checking profiles from ${PROFILES_SOURCE} against logprof"
	$(Q)${LOGPROF} -d ${PROFILES_SOURCE} -f /dev/null
