COMMONDIR=../../common/

all:
include common/Make.rules

COMMONDIR_EXISTS=$(strip $(shell [ -d ${COMMONDIR} ] && echo true))
ifeq ($(COMMONDIR_EXISTS), true)
common/Make.rules: $(COMMONDIR)/Make.rules
	ln -sf $(COMMONDIR) .
endif

MANPAGES=apparmor.vim.5
VIM_INSTALL_PATH=${DESTDIR}/usr/share/apparmor

all: apparmor.vim manpages htmlmanpages

apparmor.vim: apparmor.vim.in Makefile create-apparmor.vim.py
	${PYTHON} create-apparmor.vim.py > apparmor.vim

manpages: $(MANPAGES)

htmlmanpages: $(HTMLMANPAGES)

install: apparmor.vim manpages
	install -d $(VIM_INSTALL_PATH)
	install -m 644 $< $(VIM_INSTALL_PATH)
	$(MAKE) install_manpages DESTDIR=${DESTDIR}

.PHONY: check
check: check_pod_files
	#Testing with all pythons
	$(call pyalldo, create-apparmor.vim.py > /dev/null)

clean: _clean
	rm -f apparmor.vim common
