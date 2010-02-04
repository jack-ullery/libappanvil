## Process this file with automake to produce Makefile.in

SUBDIRS = po src pixmaps

EXTRA_DIST = \
	autogen.sh \
	AppArmor_Monitor_Factory.server.in

serverdir	= $(libdir)/bonobo/servers
server_in_files		= AppArmor_Monitor_Factory.server.in
server_DATA		= AppArmor_Monitor_Factory.server
AppArmor_Monitor_Factory.server:
	sed -e "s|\@LIBEXECDIR\@|$(libexecdir)|" < AppArmor_Monitor_Factory.server.in > AppArmor_Monitor_Factory.server

