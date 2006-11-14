# 	$Id: Makefile 4157 2005-03-29 23:02:21Z steve $
# ----------------------------------------------------------------------
#    Copyright (c) 2004, 2005 NOVELL (All rights reserved)
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, contact Novell, Inc.
# ----------------------------------------------------------------------
all:

# As translations get added, add them to the LANGS variable to get
# made/installed.
LANGS=ar bg bn bs ca cs cy da de el en_GB en_US es et fi fr gl he hi hr hu id it ja ka km ko lo lt mk nb nl pa pl pt_BR pt_PT pt ro ru sk sl sr sv ta tr uk vi zh_CN zh_TW

include ../common/Make-po.rules
../common/Make-po.rules:
	make -C .. common/Make.rules

XGETTEXT_ARGS+=--language=perl
