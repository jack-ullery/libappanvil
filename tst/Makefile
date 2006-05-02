#
# $Id: Makefile 4312 2005-04-17 07:41:31Z steve $
#
PROVE=/usr/bin/prove -v
TESTS=simple.pl

all: tests

.PHONY: tests
tests: ../apparmor_parser
	pushd . && ${PROVE} ${TESTS} && popd

../apparmor_parser:
	make -C .. apparmor_parser
