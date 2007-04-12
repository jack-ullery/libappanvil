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

MANPAGES			=
DOCUMENTS                       = immunix.css
PAPERS=$(wildcard papers/*)

# All manpages are now autotragically generated.
GENERATED=${MANPAGES} ${HTMLMANPAGES}

all: $(GENERATED) techdoc.pdf

help:
	@echo "This makefile is for creating a releases only."
	@echo "Please select release or rpm as targets."

techdoc.pdf: techdoc.tex
	while pdflatex $< || exit 1; \
	      grep -q "Label(s) may have changed" techdoc.log; \
	do :; done

%.txt: %.pdf
	pdftotext $<

techdoc/index.html: techdoc.pdf
	latex2html -show_section_numbers -split 0 -noinfo -nonavigation -noaddress techdoc.tex

.PHONY: release
release: $(TARBALL)

.PHONY: clean
clean:
	-rm -f $(GENERATED) $(TARBALL) $(NAME)-$(VERSION)*.tar.gz Make.rules pod2*.tmp techdoc.{aux,log,pdf,toc}
	-rm -rf techdoc/

.PHONY: install_documents
install_documents: ${HTMLMANPAGES}
	mkdir -m 755 -p ${DESTDIR}/${DOCDIR}
	install -m 644 $(DOCUMENTS) ${HTMLMANPAGES} ${DESTDIR}/${DOCDIR}

.PHONY: install
install: install_manpages install_documents

