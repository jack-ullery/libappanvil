#! /bin/bash
# $Id: symlink.sh 6040 2006-01-11 00:15:48Z tonyj $

#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME symlink
#=DESCRIPTION As the 'link' test but for symbolic rather than hard links

echo "symlink mediation in AppArmor has been removed"; exit 1

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

src1=$tmpdir/src1
src2=$tmpdir/src2
src3=$tmpdir/src3
target=$tmpdir/target
path2=target
path3=$(echo $tmpdir | sed -e "s|/[^/]*|../|g")${target}
okperm=rwixl
badperm=rwl
nolinkperm=rwix

touch $target 

# PASS TEST

genprofile ${src1}:$okperm ${src2}:$okperm ${src3}:$okperm $target:$nolinkperm

runchecktest "MATCHING PERM (absolute)" pass $target ${src1}
runchecktest "MATCHING PERM (same dir)" pass ${path2} ${src2} 
runchecktest "MATCHING PERM (relative)" pass ${path3} ${src3}

# FAILURE TEST

rm -f ${src1} ${src2} ${src3}

genprofile ${src1}:$badperm ${src2}:$badperm ${src3}:$badperm $target:$nolinkperm

runchecktest "NONMATCHING PERM (absolute)" fail $target ${src1}
runchecktest "NONMATCHING PERM (same dir)" fail ${path2} ${src2} 
runchecktest "NONMATCHING PERM (relative)" fail ${path3} ${src3}

# NOLINK TEST

rm -f ${src1} ${src2} ${src3}

genprofile ${src1}:$nolinkperm ${src2}:$nolinkperm ${src3}:$nolinkperm $target:$nolinkperm

runchecktest "NOLINK PERM (absolute)" fail $target ${src1}
runchecktest "NOLINK PERM (same dir)" fail ${path2} ${src2}
runchecktest "NOLINK PERM (relative)" fail ${path3} ${src3}
