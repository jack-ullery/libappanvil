# $Id$
# ----------------------------------------------------------------------
#    Copyright (c) 2004, 2005 NOVELL (All rights reserved)
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
# stuff to make a release tarball
NAME:=apparmor-docs
COMMONDIR:=$(strip $(shell if [ -d "../common/" ] ; then \
		     echo "../common/" ; \
		   elif [ -d "../../common/" ] ; then \
		     echo "../../common/" ; \
                   else \
		     echo "/common_dir_not_found" ; \
                   fi))
all:

include common/Make.rules

COMMONDIR_EXISTS=$(strip $(shell [ -d ${COMMONDIR} ] && echo true))
ifeq ($(COMMONDIR_EXISTS), true)
common/Make.rules: ${COMMONDIR}/Make.rules
	ln -sf ${COMMONDIR} .
endif

RELEASE_DIR                     = ${NAME}-${VERSION}
DOCDIR                          = /usr/share/doc/${NAME}-${VERSION}

AA_MANPAGES			= autodep.8 complain.8 enforce.8 logprof.8 genprof.8 \
				  unconfined.8
MANPAGES			= logprof.conf.5 \
				  ${AA_MANPAGES} \
				  apparmor_status.8 mod_apparmor.8
DOCUMENTS                       = immunix.css
PAPERS=$(wildcard papers/*)

HTMLMANPAGES=$(foreach manpage, ${MANPAGES}, ${manpage}.html)
# All manpages are now autotragically generated.
GENERATED=${MANPAGES} ${HTMLMANPAGES}

all: $(GENERATED)

help:
	@echo "This makefile is for creating a releases only."
	@echo "Please select release or rpm as targets."

.PHONY: release
release: $(TARBALL)

.PHONY: clean
clean:
	-rm -f $(GENERATED) $(TARBALL) $(NAME)-$(VERSION)*.tar.gz Make.rules pod2*.tmp

.PHONY: install_manpages
install_manpages: $(MANPAGES)
	for dir in ${MANDIRS} ; do install -d ${DESTDIR}/${MANDIR}/man$${dir} ; done
	$(foreach dir, ${MANDIRS}, \
	     install -m 644 $(filter %.${dir}, ${MANPAGES}) ${DESTDIR}/${MANDIR}/man${dir}; \
	     $(foreach aa_page, $(filter %.${dir}, ${AA_MANPAGES}), \
	     	ln -sf $(aa_page) ${DESTDIR}/${MANDIR}/man${dir}/${aa_page:%=aa-%};)) 
	# special case for apparmor_status
	ln -sf apparmor_status.8 ${DESTDIR}/${MANDIR}/man8/aa-status.8

.PHONY: install_documents
install_documents: ${HTMLMANPAGES}
	mkdir -m 755 -p ${DESTDIR}/${DOCDIR}
	install -m 644 $(DOCUMENTS) ${HTMLMANPAGES} ${DESTDIR}/${DOCDIR}

.PHONY: install
install: install_manpages install_documents

