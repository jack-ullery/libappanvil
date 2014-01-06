AUTOMAKE_OPTIONS = foreign 1.4
NAME = libapparmor
SRCDIR = src

SUBDIRS = doc src include swig testsuite

REPO_VERSION=$(shell if [ -x /usr/bin/svn ] ; then \
	/usr/bin/svn info . 2> /dev/null | grep "^Last Changed Rev:" | sed "s/^Last Changed Rev: //" ; \
	fi)

REPO_URL=$(shell if [ -x /usr/bin/svn ] ; then \
	/usr/bin/svn info . 2> /dev/null | grep "^URL:" | sed "s/^URL: //" ; \
	fi)
RELEASE_DIR     = $(NAME)-$(VERSION)-${REPO_VERSION}

SVNTARBALL = $(NAME)-$(VERSION)-${REPO_VERSION}.tar.gz
SVNTAR = /bin/tar czvp -h --exclude .svn --exclude CVS --exclude .cvsignore --exclude ${SVNTARBALL} --exclude ${RELEASE_DIR}/${RELEASE_DIR}  $(shell test -f ${NAME}.exclude && echo "-X ${NAME}.exclude")

distball: clean
	rm -rf $(RELEASE_DIR)
	svn export -r $(REPO_VERSION) $(REPO_URL) $(RELEASE_DIR)
	$(SVNTAR) -f $(SVNTARBALL) $(RELEASE_DIR)
	rm -rf $(RELEASE_DIR)
	
EXTRA_DIST = AUTHORS ChangeLog COPYING.LGPL INSTALL NEWS README
