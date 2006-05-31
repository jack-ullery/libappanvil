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
	$(Q)pushd . && ${PROVE} ${PROVE_ARG} ${TESTS} && popd

../apparmor_parser:
	make -C .. apparmor_parser
