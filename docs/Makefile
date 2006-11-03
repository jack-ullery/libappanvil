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

POD2MAN				= /usr/bin/pod2man
POD2HTML			= /usr/bin/pod2html
RELEASE_DIR                     = ${NAME}-${VERSION}
MANDIRS                         = 2 5 7 8
MANDIR                          = /usr/share/man
DOCDIR                          = /usr/share/doc/${NAME}-${VERSION}

AA_MANPAGES			= autodep.8 complain.8 enforce.8 logprof.8 genprof.8 \
				  unconfined.8
MANPAGES			= change_hat.2 \
				  subdomain.conf.5 apparmor.d.5 apparmor.vim.5 logprof.conf.5 \
				  apparmor.7 \
				  ${AA_MANPAGES} \
				  apparmor_parser.8 apparmor_status.8 mod_apparmor.8
OLD_MANPAGES			= subdomain.d.5 subdomain.vim.5 \
				  subdomain.7 subdomain_parser.8
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
	-rm -f $(GENERATED) $(TARBALL) $(NAME)-$(VERSION)*.tar.gz

# I'm pretty sure the following could be in a foreach loop, but I'm too
# lazy to code it up.

%.1: %.pod
	$(POD2MAN) $< --release=NOVELL/SUSE --center=AppArmor --section=1 > $@

%.2: %.pod
	$(POD2MAN) $< --release=NOVELL/SUSE --center=AppArmor --section=2 > $@

%.5: %.pod
	$(POD2MAN) $< --release=NOVELL/SUSE --center=AppArmor --section=5 > $@

%.7: %.pod
	$(POD2MAN) $< --release=NOVELL/SUSE --center=AppArmor --section=7 > $@

%.8: %.pod
	$(POD2MAN) $< --release=NOVELL/SUSE --center=AppArmor --section=8 > $@

%.1.html: %.pod
	$(POD2HTML) --header --css immunix.css --infile=$< --outfile=$@ 

%.2.html: %.pod
	$(POD2HTML) --header --css immunix.css --infile=$< --outfile=$@ 

%.5.html: %.pod
	$(POD2HTML) --header --css immunix.css --infile=$< --outfile=$@ 

%.7.html: %.pod
	$(POD2HTML) --header --css immunix.css --infile=$< --outfile=$@ 

%.8.html: %.pod
	$(POD2HTML) --header --css immunix.css --infile=$< --outfile=$@ 

.PHONY: install_manpages
install_manpages: $(MANPAGES)
	for dir in ${MANDIRS} ; do install -d ${DESTDIR}/${MANDIR}/man$${dir} ; done
	$(foreach dir, ${MANDIRS}, \
	     install -m 644 $(filter %.${dir}, ${MANPAGES}) ${DESTDIR}/${MANDIR}/man${dir}; \
	     $(foreach oldpage, $(filter %.${dir}, ${OLD_MANPAGES}), \
	     	ln -sf $(oldpage:subdomain%=apparmor%) ${DESTDIR}/${MANDIR}/man${dir}/${oldpage};) \
	     $(foreach aa_page, $(filter %.${dir}, ${AA_MANPAGES}), \
	     	ln -sf $(aa_page) ${DESTDIR}/${MANDIR}/man${dir}/${aa_page:%=aa-%};)) 
	# special case for apparmor_status
	ln -sf apparmor_status.8 ${DESTDIR}/${MANDIR}/man8/aa-status.8

.PHONY: install_documents
install_documents: ${HTMLMANPAGES}
	mkdir -m 755 -p ${DESTDIR}/${DOCDIR} ${DESTDIR}/${DOCDIR}/papers
	install -m 644 $(DOCUMENTS) ${HTMLMANPAGES} ${DESTDIR}/${DOCDIR}
	install -m 644 -D ${PAPERS} ${DESTDIR}/${DOCDIR}/papers

.PHONY: install
install: install_manpages install_documents

