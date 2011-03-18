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
NAME:=apache2-mod_apparmor
all:
COMMONDIR=../../common/

include common/Make.rules

COMMONDIR_EXISTS=$(strip $(shell [ -d ${COMMONDIR} ] && echo true))
ifeq ($(COMMONDIR_EXISTS), true)
common/Make.rules: $(COMMONDIR)/Make.rules
	ln -sf $(COMMONDIR) .
endif

TARGET:=mod_apparmor.so
MANPAGES=mod_apparmor.8

APXS:=$(shell if [ -x "/usr/sbin/apxs2" ] ; then \
		echo "/usr/sbin/apxs2" ; \
              elif [ -x "/usr/sbin/apxs" ] ; then \
	        echo "/usr/sbin/apxs" ; \
              elif [ -x "/usr/bin/apxs2" ] ; then \
	        echo "/usr/bin/apxs2" ; \
              elif [ -x "/usr/bin/apxs" ] ; then \
	        echo "/usr/bin/apxs" ; \
              else \
	        echo "apxs" ; \
	      fi ) 
APXS_INSTALL_DIR=$(shell ${APXS} -q LIBEXECDIR)
DESTDIR=
# Need to pass -Wl twice here to get past both apxs2 and libtool, as
# libtool will add the path to the RPATH of the library if passed -L/some/path
LIBAPPARMOR_FLAGS=-I../../libraries/libapparmor/src -Wl,-Wl,-L../../libraries/libapparmor/src/.libs
LDLIBS=-lapparmor

all: $(TARGET) ${MANPAGES} ${HTMLMANPAGES}

%.so: %.c
	${APXS} ${LIBAPPARMOR_FLAGS} -c $< ${LDLIBS}
	mv .libs/$@ .

.PHONY: install
install: ${TARGET} ${MANPAGES}
	mkdir -p ${DESTDIR}/${APXS_INSTALL_DIR}
	install -m 755 $< ${DESTDIR}/${APXS_INSTALL_DIR}
	make install_manpages DESTDIR=${DESTDIR}

.PHONY: clean
clean: _clean
	rm -rf .libs
	rm -f *.la *.lo *.so *.o *.slo Make.rules
