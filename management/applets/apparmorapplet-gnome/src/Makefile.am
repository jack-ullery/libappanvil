## Process this file with automake to produce Makefile.in

INCLUDES = \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(prefix)/$(DATADIRNAME)/locale"\" \
	-DGNOMELOCALEDIR=\""$(prefix)/$(DATADIRNAME)/locale"\" \
	-DDBUS_API_SUBJECT_TO_CHANGE \
	`$(PKG_CONFIG) --cflags libpanelapplet-2.0` \
	`$(PKG_CONFIG) --cflags dbus-1` \
	@PACKAGE_CFLAGS@

LIBS = \
	`$(PKG_CONFIG) --libs libpanelapplet-2.0` \
	`$(PKG_CONFIG) --libs dbus-1` \
	@PACKAGE_LIBS@

bin_PROGRAMS = apparmorapplet

apparmorapplet_SOURCES = \
	apparmor-applet.c apparmor-applet.h \
	preferences_dialog.c preferences_dialog.h \
	reject_list.c reject_list.h

apparmorapplet_LDADD = @PACKAGE_LIBS@ $(INTLLIBS)

