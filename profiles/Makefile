# ------------------------------------------------------------------
#
#    Copyright (C) 2002-2005 Novell/SUSE
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------


# Makefile for LSM-based SubDomain SuSE profiles

NAME=apparmor-profiles
ALL:
COMMONDIR=../../common/

include Make.rules

COMMONDIR_EXISTS=$(strip $(shell [ -d ${COMMONDIR} ] && echo true))
ifeq ($(COMMONDIR_EXISTS), true)
Make.rules: $(COMMONDIR)/Make.rules
	ln -f $(COMMONDIR)/Make.rules
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
	-rm -f $(NAME)-$(VERSION)*.tar.gz
