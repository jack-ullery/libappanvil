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
MAKE_RULES=common/Make.rules

include ${MAKE_RULES}

COMMONDIR_EXISTS=$(strip $(shell [ -d ${COMMONDIR} ] && echo true))
ifeq ($(COMMONDIR_EXISTS), true)
common/Make.rules: $(COMMONDIR)/Make.rules
	ln -sf $(COMMONDIR) .
endif

EXTRA_CFLAGS=$(CFLAGS) -fPIC -shared -Wall -I../../libraries/libapparmor/src/
LINK_FLAGS=-Xlinker -x -L../../libraries/libapparmor/src/.libs
LIBS=-lpam -lapparmor
OBJECTS=${NAME}.o get_options.o

all: $(NAME).so

$(NAME).so: ${OBJECTS}
	$(CC) $(EXTRA_CFLAGS) $(LINK_FLAGS) -o $@ ${OBJECTS} $(LIBS)

%.o: %.c
	$(CC) $(EXTRA_CFLAGS) -c -o $@ $<

# need some better way of determining this
DESTDIR=/
SECDIR ?= ${DESTDIR}/lib/security

.PHONY: install
install: $(NAME).so
	install -m 755 -d $(SECDIR)
	install -m 555 $(NAME).so $(SECDIR)/
	
.PHONY: clean
clean: ${MAKE_RULES}
	rm -f core core.* *.so *.o *.s *.a *~
	rm -f ${NAME}-*.tar.gz Make.rules

