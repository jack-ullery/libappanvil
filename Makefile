#
# $Id$
#

include common/Make.rules

DIRS=parser \
     profiles \
     utils \
     changehat/libapparmor \
     changehat/mod_apparmor \
     changehat/pam_apparmor \
     management/yastui \
     common \
     tests

RELEASE_DIR=apparmor-${VERSION}-${REPO_VERSION}

_dist: clean
	mkdir ${RELEASE_DIR}
	for dir in ${DIRS} ; do \
		svn export -r $(REPO_VERSION) $(REPO_URL)/$${dir} $(RELEASE_DIR)/$${dir} ; \
	done
	
clean:
	-rm -rf ${RELEASE_DIR}
