#! /bin/bash
# $Id$

#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME link
#=DESCRIPTION 
# Link requires 'l' permission and that permissions on the src and target 
# must match.  This test verifies matching, non-matching and missing link 
# permissions in a profile.
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

src=$tmpdir/src
target=$tmpdir/target
okperm=rwixl
badperm=rwl
nolinkperm=rwix

touch $src 

# PASS TEST

genprofile $src:$okperm $target:$okperm
runchecktest "MATCHING PERM (rwixl)" pass $src $target

# PASS TEST

rm -f $target

genprofile $src:$nolinkperm $target:$okperm
runchecktest "MATCHING PERM (rwix)" pass $src $target

# PASS TEST

rm -f $target

genprofile $src:r $target:rl
runchecktest "MATCHING PERM (r)" pass $src $target

# PASS TEST

rm -f $target

genprofile $src:w $target:wl
runchecktest "MATCHING PERM (w)" pass $src $target

# FAILURE TEST

rm -f $target

genprofile $src:$okperm $target:$badperm
runchecktest "NONMATCHING PERM" fail $src $target

# NOLINK TEST

rm -f $target

genprofile $src:$okperm $target:$nolinkperm
runchecktest "NOLINK PERM" fail $src $target
