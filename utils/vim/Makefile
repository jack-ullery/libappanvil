COMMONDIR=../../common/

all:
include common/Make.rules

COMMONDIR_EXISTS=$(strip $(shell [ -d ${COMMONDIR} ] && echo true))
ifeq ($(COMMONDIR_EXISTS), true)
common/Make.rules: $(COMMONDIR)/Make.rules
	ln -sf $(COMMONDIR) .
endif

VIM_INSTALL_PATH=${DESTDIR}/usr/share/apparmor

all: apparmor.vim

apparmor.vim: apparmor.vim.in Makefile create-apparmor.vim.py
	python create-apparmor.vim.py > $@

install: apparmor.vim
	install -d $(VIM_INSTALL_PATH)
	install -m 644 $< $(VIM_INSTALL_PATH)


clean:
	rm -f apparmor.vim common
