COMMONDIR=../../common/

all:
include common/Make.rules

COMMONDIR_EXISTS=$(strip $(shell [ -d ${COMMONDIR} ] && echo true))
ifeq ($(COMMONDIR_EXISTS), true)
common/Make.rules: $(COMMONDIR)/Make.rules
	ln -sf $(COMMONDIR) .
endif

all: apparmor.vim

apparmor.vim: apparmor.vim.in Makefile create-apparmor.vim.py
	python create-apparmor.vim.py > $@

clean:
	rm -f apparmor.vim
