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
LANGS=ar bg bn bs ca cs cy da de_DE de el en_GB en_US es_ES es et fi fr_FR fr gl he hi hr hu_HU hu id it_IT it ja_JP ja ka km ko la_PG lo lt mk nb_NO nb nl pa pl pt_BR pt pt_PT ro ru sk sl sr sv ta tr uk vi zh_CN zh_TW

include ../common/Make-po.rules
../common/Make-po.rules:
	make -C .. common/Make.rules

XGETTEXT_ARGS+=--language=perl
