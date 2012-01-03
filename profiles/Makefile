# ------------------------------------------------------------------
#
#    Copyright (C) 2002-2009 Novell/SUSE
#    Copyright (C) 2010 Canonical Ltd.
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

# Makefile for LSM-based AppArmor profiles

NAME=apparmor-profiles
ALL: local
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
SUBDIRS_MUST_BE_SKIPPED=${PROFILES_SOURCE}/abstractions ${PROFILES_SOURCE}/apache2.d ${PROFILES_SOURCE}/program-chunks ${PROFILES_SOURCE}/tunables ${PROFILES_SOURCE}/local
PROFILES_TO_COPY=$(filter-out ${SUBDIRS_MUST_BE_SKIPPED}, $(wildcard ${PROFILES_SOURCE}/*))
TUNABLES_TO_COPY=$(filter-out ${PROFILES_SOURCE}/tunables/home.d ${PROFILES_SOURCE}/tunables/multiarch.d, $(wildcard ${PROFILES_SOURCE}/tunables/*))
ABSTRACTIONS_TO_COPY=$(filter-out ${PROFILES_SOURCE}/abstractions/ubuntu-browsers.d, $(wildcard ${PROFILES_SOURCE}/abstractions/*))

local:
	for profile in ${PROFILES_TO_COPY}; do \
		fn=$$(basename $$profile); \
		echo "# Site-specific additions and overrides for '$$fn'" > ${PROFILES_SOURCE}/local/$$fn; \
	done; \

.PHONY: install
install: local
	install -m 755 -d ${PROFILES_DEST}
	install -m 755 -d ${PROFILES_DEST}/abstractions \
                          ${PROFILES_DEST}/apache2.d \
                          ${PROFILES_DEST}/disable \
                          ${PROFILES_DEST}/program-chunks \
                          ${PROFILES_DEST}/tunables \
                          ${PROFILES_DEST}/tunables/home.d \
                          ${PROFILES_DEST}/tunables/multiarch.d \
                          ${PROFILES_DEST}/local
	install -m 644 ${PROFILES_TO_COPY} ${PROFILES_DEST}
	install -m 644 ${ABSTRACTIONS_TO_COPY} ${PROFILES_DEST}/abstractions
	install -m 755 -d ${PROFILES_DEST}/abstractions/ubuntu-browsers.d
	install -m 644 ${PROFILES_SOURCE}/abstractions/ubuntu-browsers.d/* ${PROFILES_DEST}/abstractions/ubuntu-browsers.d
	install -m 644 ${PROFILES_SOURCE}/apache2.d/* ${PROFILES_DEST}/apache2.d
	install -m 644 ${PROFILES_SOURCE}/program-chunks/* ${PROFILES_DEST}/program-chunks
	install -m 644 ${TUNABLES_TO_COPY} ${PROFILES_DEST}/tunables
	install -m 644 ${PROFILES_SOURCE}/tunables/home.d/* ${PROFILES_DEST}/tunables/home.d
	install -m 644 ${PROFILES_SOURCE}/tunables/multiarch.d/* ${PROFILES_DEST}/tunables/multiarch.d
	install -m 755 -d ${EXTRAS_DEST}
	install -m 644 ${EXTRAS_SOURCE}/* ${EXTRAS_DEST}
	install -m 644 ${PROFILES_SOURCE}/local/* ${PROFILES_DEST}/local

LOCAL_ADDITIONS=$(filter-out ${PROFILES_SOURCE}/local/README, $(wildcard ${PROFILES_SOURCE}/local/*))
.PHONY: clean
clean:
	-rm -f $(NAME)-$(VERSION)*.tar.gz Make.rules ${LOCAL_ADDITIONS}

ifndef VERBOSE
  Q=@
else
  Q=
endif

ifndef PARSER
# use system parser
PARSER=../parser/apparmor_parser
endif

ifndef LOGPROF
# use ../utils logprof
LOGPROF=perl -I../utils/ ../utils/aa-logprof
endif

IGNORE_FILES=${EXTRAS_SOURCE}/README
CHECK_PROFILES=$(filter-out ${IGNORE_FILES} ${SUBDIRS_MUST_BE_SKIPPED}, $(wildcard ${PROFILES_SOURCE}/*) $(wildcard ${EXTRAS_SOURCE}/*))

.PHONY: check
check:
	@echo "*** Checking profiles from ${PROFILES_SOURCE} and ${EXTRAS_SOURCE} against apparmor_parser"
	$(Q)for profile in ${CHECK_PROFILES} ; do \
		${PARSER} -S -b ${PWD}/apparmor.d $${profile} > /dev/null || exit 1; \
	done
	@echo "*** Checking profiles from ${PROFILES_SOURCE} against logprof"
	$(Q)${LOGPROF} -d ${PROFILES_SOURCE} -f /dev/null || exit 1
