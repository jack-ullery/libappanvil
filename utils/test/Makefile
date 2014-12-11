# ----------------------------------------------------------------------
#    Copyright (c) 1999, 2004-2009 NOVELL (All rights reserved)
#    Copyright (c) 2010-2014 Canonical Ltd.
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
NAME 		= apparmor-utils
all:
COMMONDIR=../../common/

include common/Make.rules

COMMONDIR_EXISTS=$(strip $(shell [ -d ${COMMONDIR} ] && echo true))
ifeq ($(COMMONDIR_EXISTS), true)
common/Make.rules: $(COMMONDIR)/Make.rules
	ln -sf $(COMMONDIR) .
endif

COVERAGE_OMIT=test-*.py,common_test.py
ifneq ($(COVERAGE_OUT), )
HTML_COVR_ARGS=-d $(COVERAGE_OUT)
endif

.PHONY: clean check coverage coverage-report coverage-html
ifndef VERBOSE
.SILENT: clean check .coverage coverage coverage-report coverage-html
endif

clean: _clean
	rm -rf __pycache__/ common .coverage htmlcov

check:
	export PYTHONPATH=.. ; $(foreach test, $(wildcard test-*.py), $(call pyalldo, $(test)))

.coverage: $(wildcard ../aa-* ../apparmor/*.py test-*.py)
	export PYTHONPATH=.. ; $(foreach test, $(wildcard test-*.py), $(PYTHON) -m coverage run --branch -p $(test); )
	$(PYTHON) -m coverage combine

coverage: .coverage

coverage-report: .coverage
	$(PYTHON) -m coverage report --omit="$(COVERAGE_OMIT)"

coverage-html: .coverage
	$(PYTHON) -m coverage html --omit="$(COVERAGE_OMIT)" $(HTML_COVR_ARGS)

