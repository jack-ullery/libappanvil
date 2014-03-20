#
#
OVERRIDE_TARBALL=yes

include common/Make.rules

DIRS=parser \
     profiles \
     utils \
     libraries/libapparmor \
     changehat/mod_apparmor \
     changehat/pam_apparmor \
     tests

#REPO_URL?=lp:apparmor
# --per-file-timestamps is failing over SSH, https://bugs.launchpad.net/bzr/+bug/1257078
REPO_URL?=https://code.launchpad.net/~apparmor-dev/apparmor/master
# alternate possibilities to export from
#REPO_URL=.
#REPO_URL="bzr+ssh://bazaar.launchpad.net/~sbeattie/+junk/apparmor-dev/"

RELEASE_DIR=apparmor-${VERSION}
__SETUP_DIR?=.

# We create a separate version for tags because git can't handle tags
# with embedded ~s in them. No spaces around '-' or they'll get
# embedded in ${VERSION}
TAG_VERSION=$(subst ~,-,${VERSION})

# Add exclusion entries arguments for tar here, of the form:
#   --exclude dir_to_exclude --exclude other_dir
TAR_EXCLUSIONS=

.PHONY: tarball
tarball: clean
	REPO_VERSION=`$(value REPO_VERSION_CMD)` ; \
	make export_dir __EXPORT_DIR=${RELEASE_DIR} __REPO_VERSION=$${REPO_VERSION} ; \
	make setup __SETUP_DIR=${RELEASE_DIR} ; \
	tar ${TAR_EXCLUSIONS} -cvzf ${RELEASE_DIR}.tar.gz ${RELEASE_DIR}

.PHONY: snapshot
snapshot: clean
	REPO_VERSION=`$(value REPO_VERSION_CMD)` ; \
	SNAPSHOT_DIR=apparmor-${VERSION}~$${REPO_VERSION} ;\
	make export_dir __EXPORT_DIR=$${SNAPSHOT_DIR} __REPO_VERSION=$${REPO_VERSION} ; \
	make setup __SETUP_DIR=$${SNAPSHOT_DIR} ; \
	tar ${TAR_EXCLUSIONS} -cvzf $${SNAPSHOT_DIR}.tar.gz $${SNAPSHOT_DIR} ;


.PHONY: export_dir
export_dir:
	mkdir $(__EXPORT_DIR)
	/usr/bin/bzr export --per-file-timestamps -r $(__REPO_VERSION) $(__EXPORT_DIR) $(REPO_URL)
	echo "$(REPO_URL) $(__REPO_VERSION)" > $(__EXPORT_DIR)/common/.stamp_rev

.PHONY: clean
clean:
	-rm -rf ${RELEASE_DIR} ./apparmor-${VERSION}~*
	for dir in $(DIRS); do \
		make -C $$dir clean; \
	done

.PHONY: setup
setup:
	cd $(__SETUP_DIR)/libraries/libapparmor && ./autogen.sh

.PHONY: tag
tag:
	bzr tag apparmor_${TAG_VERSION}

