# $Id$
# ----------------------------------------------------------------------
#    Copyright (c) 2004, 2005, 2006 NOVELL (All rights reserved)
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of version 2.1 of the GNU Lesser
#   General Public License published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU Lesser General Public
#   License along with this program; if not, contact Novell, Inc.
# ----------------------------------------------------------------------
NAME := libapparmor
all:
COMMONDIR:=$(strip $(shell if [ -d "../common/" ] ; then \
                     echo "../common/" ; \
	     elif [ -d "../../common/" ] ; then \
		     echo "../../common/" ; \
	     else \
	             echo "/common_dir_not_found" ; \
	     fi))

include Make.rules

COMMONDIR_EXISTS=$(strip $(shell [ -d ${COMMONDIR} ] && echo true))
ifeq ($(COMMONDIR_EXISTS), true)
Make.rules: $(COMMONDIR)/Make.rules
	ln -f $(COMMONDIR)/Make.rules .
endif

SO_VERS		= 1
DESTDIR         = 
LIB             = lib/
LIBDIR          = /usr/${LIB}

TARGET=libapparmor
TARGETS=${TARGET}.so ${TARGET}.a

OLDTARGET=libimmunix.so.1

OBJECTS=change_hat.o
TESTS=tst-sgdh tst-cdh tst-sgkey tst-sgdh-static tst-cdh-static tst-sgkey-static

CFLAGS=-g -O2 -Wall -Wstrict-prototypes -pipe
EXTRA_CFLAGS=$(CFLAGS) -fpic -D_REENTRANT
ARFLAGS=-rcs

TEST_CFLAGS=$(CFLAGS) $(CANARY_FLAG) $(FORMATGUARD_FLAG)
TEST_LDFLAGS= -L. -limmunix

all: ${TARGETS} ${OLDTARGET}

%.o: %.c
	$(CC) ${EXTRA_CFLAGS} -c -shared -o $@ $<

${TARGET}.so: ${OBJECTS}
	${CC} ${EXTRA_CFLAGS} -o $@.$(SO_VERS) -Wl,-soname,$@.$(SO_VERS) -Wl,--version-script=${TARGET}.map -W,-z,defs -shared -dynamic  $^
	ln -fs $@.$(SO_VERS) $@

${OLDTARGET}: ${OBJECTS} libimmunix_warning.o
	${CC} ${EXTRA_CFLAGS} -o $@ -Wl,-soname,$@ -Wl,--version-script=${TARGET}.map -W,-z,defs -shared -dynamic $^

${TARGET}.a: ${OBJECTS}
	ar ${ARFLAGS} $@ $^

${POSTINSTALLBIN}: ${POSTINSTALLBIN}.c
	$(CC) -static -Os -o $@ $(CANARY_FLAG) $(FORMATGUARD_FLAG) $^

# Ugh, dunno how to do an auto rule for the TESTS
tst-sgdh: tst-sgdh.c ${TARGET}.so
	$(CC) ${TEST_CFLAGS} -o $@ $< ${TEST_LDFLAGS}

tst-cdh: tst-cdh.c ${TARGET}.so
	$(CC) ${TEST_CFLAGS} -o $@ $< ${TEST_LDFLAGS}

tst-sgkey: tst-sgkey.c ${TARGET}.so
	$(CC) ${TEST_CFLAGS} -o $@ $< ${TEST_LDFLAGS}

tst-sgdh-static: tst-sgdh.c ${TARGET}.a
	$(CC) -static ${TEST_CFLAGS} -o $@ $< ${TEST_LDFLAGS}

tst-cdh-static: tst-cdh.c ${TARGET}.a
	$(CC) -static ${TEST_CFLAGS} -o $@ $< ${TEST_LDFLAGS}

tst-sgkey-static: tst-sgkey.c ${TARGET}.a
	$(CC) -static ${TEST_CFLAGS} -o $@ $< ${TEST_LDFLAGS}

check: $(TESTS)
	-LD_LIBRARY_PATH=. ./tst-sgdh
	-LD_LIBRARY_PATH=. ./tst-cdh
	-LD_LIBRARY_PATH=. ./tst-sgkey
	-./tst-sgdh-static
	-./tst-cdh-static
	-./tst-sgkey-static

.PHONY: install
install: $(TARGETS)
	install -d $(DESTDIR)/${LIB} $(DESTDIR)${LIBDIR}
	install -d ${DESTDIR}/usr/include/sys
	mv -f $(TARGET).so.$(SO_VERS) $(TARGET)-$(VERSION)-$(RELEASE).so.$(SO_VERS)
	install -m 755 $(TARGET)-$(VERSION)-$(RELEASE).so.$(SO_VERS) ${DESTDIR}/${LIB}
	ln -sf $(TARGET)-$(VERSION)-$(RELEASE).so.$(SO_VERS) ${DESTDIR}/${LIB}/$(TARGET).so.$(SO_VERS)
	install -m 755 $(TARGET).a ${DESTDIR}${LIBDIR}
	install -m 644 apparmor.h ${DESTDIR}/usr/include/sys
	ln -sf /${LIB}/$(TARGET).so.$(SO_VERS) ${DESTDIR}${LIBDIR}/$(TARGET).so
	# compatability with old libimmunix
	install -m 755 $(OLDTARGET) ${DESTDIR}/${LIB}
	ln -sf apparmor.h ${DESTDIR}/usr/include/sys/immunix.h

.PHONY: clean
clean:
	rm -f *.o $(TARGET)*.so* ${TARGETS} ${OLDTARGET}
	rm -f ${NAME}-${VERSION}*.tar.gz ${TESTS} $(NAME)-*.tgz ${SPECFILE}
