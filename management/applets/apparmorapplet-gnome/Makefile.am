## Process this file with automake to produce Makefile.in

SUBDIRS = po src pixmaps

EXTRA_DIST = \
	autogen.sh \
	AppArmor_Monitor_Factory.server.in


install-data-local:
	@$(NORMAL_INSTALL)
	if test -d $(srcdir)/pixmaps; then \
	  $(mkinstalldirs) $(DESTDIR)/pixmaps; \
	  for pixmap in $(srcdir)/pixmaps/*; do \
	    if test -f $$pixmap; then \
	      $(INSTALL_DATA) $$pixmap $(pixmapsdir); \
	    fi \
	  done \
	fi

dist-hook:
	if test -d pixmaps; then \
	  mkdir $(distdir)/pixmaps; \
	  for pixmap in pixmaps/*; do \
	    if test -f $$pixmap; then \
	      cp -p $$pixmap $(distdir)/pixmaps; \
	    fi \
	  done \
	fi


serverdir	= $(libdir)/bonobo/servers
server_in_files		= AppArmor_Monitor_Factory.server.in
server_DATA		= AppArmor_Monitor_Factory.server
AppArmor_Monitor_Factory.server:
	sed -e "s|\@LIBEXECDIR\@|$(libexecdir)|" < AppArmor_Monitor_Factory.server.in > AppArmor_Monitor_Factory.server

