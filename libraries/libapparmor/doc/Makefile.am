## Process this file with automake to produce Makefile.in

POD2MAN = pod2man
PODCHECKER = podchecker

# No perl, no manpages
if HAVE_PERL

man_MANS = aa_change_hat.2 aa_change_profile.2 aa_getcon.2 aa_find_mountpoint.2

PODS = $(subst .2,.pod,$(man_MANS))

EXTRA_DIST = $(man_MANS) $(PODS)

## delete man pages at maintainer-clean
BUILT_SOURCES = $(man_MANS)

%.2: %.pod
	$(PODCHECKER) -warnings -warnings $<
	$(POD2MAN) \
		--section=2 \
		--release="AppArmor $(VERSION)" \
		--center="AppArmor" \
		--stderr \
		$< > $@

endif
