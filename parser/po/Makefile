# 	$Id: Makefile 4157 2005-03-29 23:02:21Z steve $
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
LANGS=de_DE en_US es_ES fr_FR hu_HU it_IT ja_JP nb_NO pt_BR pt_PT \
	zh_CN zh_TW

COMMONDIR=../../../common/

include Make.rules

XGETTEXT_ARGS+=--language=C --keyword=_ $(shell if [ -f ${NAME}.pot ] ; then echo -n -j ; fi)

COMMONDIR_EXISTS=$(strip $(shell [ -d ${COMMONDIR} ] && echo true))
ifeq ($(COMMONDIR_EXISTS), true)
Make.rules: $(COMMONDIR)/Make-po.rules
	ln -f $(COMMONDIR)/Make-po.rules $@
endif

