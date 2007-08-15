POD2MAN = pod2man

man_MANS = change_hat.2

PODS = $(subst .2,.pod,$(man_MANS))

EXTRA_DIST = $(man_MANS) $(PODS)

## delete man pages at maintainer-clean
BUILT_SOURCES = $(man_MANS)

%.2: %.pod
	$(POD2MAN) \
		--section=2 \
		--release="NOVELL/SUSE" \
		--center="AppArmor" \
		--date="2007-07-27" \
		$< > $@
$
