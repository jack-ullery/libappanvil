# 	$Id: Makefile 5900 2005-12-08 19:12:56Z steve $
# ----------------------------------------------------------------------
#    Copyright (c) 1999, 2004, 2005 NOVELL (All rights reserved)
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
NAME=pam_apparmor
all:
COMMONDIR=../../common/

include Make.rules

COMMONDIR_EXISTS=$(strip $(shell [ -d ${COMMONDIR} ] && echo true))
ifeq ($(COMMONDIR_EXISTS), true)
Make.rules: $(COMMONDIR)/Make.rules 
	ln -f $(COMMONDIR)/Make.rules .
endif

CFLAGS=-fPIC -shared -Xlinker -x
LIBS=-lpam -lapparmor

all: $(NAME).so

$(NAME).so: $(NAME).c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

# need some better way of determining this
DESTDIR=/
SECDIR=${DESTDIR}/lib/security

.PHONY: install
install: 
	install -d 755 $(SECDIR)
	install -m 555 $(NAME).so $(SECDIR)/
	
.PHONY: clean
clean: Make.rules
	rm -f core core.* *.so *.o *.s *.a *~ 
	rm -f $(TARBALL)

