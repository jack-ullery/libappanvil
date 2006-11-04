# 	$Id$
# ----------------------------------------------------------------------
#    Copyright (c) 2004, 2005 NOVELL (All rights reserved)
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
# ----------------------------------------------------------------------
all:

# As translations get added, add them to the LANGS variable to get
# made/installed.

# DISABLED LANGS = ar
LANGS=bg bn bs ca cs cy da de el en_GB en_US es et fi fr gl he hi hr hu id it ja ka km ko lo lt nb nl pa pl pt_BR pt ro ru sk sl sr sv ta tr uk vi zh_CN zh_TW

include ../common/Make-po.rules
../common/Make-po.rules:
	make -C .. common/Make.rules

XGETTEXT_ARGS+=--language=C --keyword=_ $(shell if [ -f ${NAME}.pot ] ; then echo -n -j ; fi)
