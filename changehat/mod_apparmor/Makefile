#	$Id$
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
SPECFILE:=apache2-mod-apparmor.spec
all:
COMMONDIR=../../common/

include Make.rules

COMMONDIR_EXISTS=$(strip $(shell [ -d ${COMMONDIR} ] && echo true))
ifeq ($(COMMONDIR_EXISTS), true)
Make.rules: $(COMMONDIR)/Make.rules
	ln -f $(COMMONDIR)/Make.rules .
endif

all: rpm

TARGET:=mod_apparmor.so
APXS:=$(shell if [ -x "/usr/sbin/apxs2" ] ; then \
		echo "/usr/sbin/apxs2" ; \
              elif [ -x "/usr/sbin/apxs" ] ; then \
	        echo "/usr/sbin/apxs" ; \
              else \
	        echo "apxs" ; \
	      fi ) 
APXS_INSTALL_DIR=$(shell ${APXS} -q LIBEXECDIR)
DESTDIR=
LIBAPPARMOR_FLAGS=$(shell if [ -f /usr/lib/libapparmor.so -o -f /usr/lib64/libapparmor.so ] ; then \
				echo -lapparmor ; \
			  else \
			  	echo -DUSE_COMPAT_IMMUNIX_H -limmunix ;\
			  fi)

%.so: %.c
	${APXS} ${LIBAPPARMOR_FLAGS} -c $<
	mv .libs/$@ .

.PHONY: install
install: ${TARGET}
	mkdir -p ${DESTDIR}/${APXS_INSTALL_DIR}
	install -m 755 $< ${DESTDIR}/${APXS_INSTALL_DIR}

.PHONY: clean
clean:
	rm -rf .libs 
	rm -f ${NAME}*.tar.gz *.la *.lo *.so *.o *.slo
