#
# $Id$
#
PROVE=/usr/bin/prove
TESTS=simple.pl

ifeq ($(VERBOSE),1)
  PROVE_ARG=-v
endif

all: tests

.PHONY: tests
tests: ../apparmor_parser
	$(Q)${PROVE} ${PROVE_ARG} ${TESTS}

../apparmor_parser:
	make -C .. apparmor_parser
