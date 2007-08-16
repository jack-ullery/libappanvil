#
# $Id$
#
OVERRIDE_TARBALL=yes

include common/Make.rules

DIRS=parser \
     profiles \
     utils \
     changehat/libapparmor \
     changehat/mod_apparmor \
     changehat/pam_apparmor \
     management/apparmor-dbus \
     management/applets/apparmorapplet-gnome \
     management/yastui \
     common \
     tests

RELEASE_DIR=apparmor-${VERSION}-${REPO_VERSION}

.PHONY: tarball
tarball: _dist
	tar cvzf ${RELEASE_DIR}.tar.gz ${RELEASE_DIR}

${RELEASE_DIR}:
	mkdir ${RELEASE_DIR}

.PHONY: _dist
.PHONY: ${DIRS}

_dist: clean ${DIRS}
	
${DIRS}: ${RELEASE_DIR}
	svn export -r $(REPO_VERSION) $(REPO_URL)/$@ $(RELEASE_DIR)/$@ ; \

clean:
	-rm -rf ${RELEASE_DIR}
