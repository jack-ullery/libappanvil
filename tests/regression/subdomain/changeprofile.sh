#! /bin/bash
# $Id: changeprofile.sh 1066 2007-12-23 01:06:30Z jrjohansen $

#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME changeprofile
#=DESCRIPTION 
# Verifies basic file access permission checks for a parent profile and one 
# subprofile/hat
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

file=$tmpdir/file
subfile=$tmpdir/file2
okperm=rw

othertest="$pwd/rw"
subtest2="$pwd//sub2"
subtest3="$pwd//sub3"


touch $file $subfile

# CHANGEPROFILE UNCONFINED
runchecktest "CHANGEPROFILE (unconfined - nochange)" pass nochange $file
runchecktest_errno ENOENT "CHANGEPROFILE (unconfined)" fail $subtest $file
genprofile image=$othertest $file:$okperm
runchecktest "CHANGEPROFILE (unconfined)" pass $othertest $file
exit

# NO CHANGEPROFILE TEST
genprofile $file:$okperm
runchecktest "NO CHANGEPROFILE (access parent file)" pass nochange $file
runchecktest "NO CHANGEPROFILE (access sub file)" fail nochange $subfile




# CHANGEPROFILE NO HATS TEST - NO PERMISSION
runchecktest "CHANGEPROFILE (no hats, nochange)" pass nochange $file
runchecktest_errno EACCES "CHANGEPROFILE (no hats, $file)" fail $subtest $file
runchecktest_errno EACCES "CHANGEPROFILE (no hats, $subfile)" fail $subtest $subfile

# CHANGEPROFILE NO HATS TEST - PERMISSION
genprofile $file:$okperm 'change_profile ->':$subtest
runchecktest "CHANGEPROFILE (no hats, nochange)" pass nochange $file
exit
runchecktest_errno ENOENT "CHANGEPROFILE (no hats, $file)" fail $subtest $file
runchecktest_errno ENOENT "CHANGEPROFILE (no hats, $subfile)" fail $subtest $subfile

# CHANGEPROFILE TEST

genprofile $file:$okperm hat:$subtest $subfile:$okperm

runchecktest "CHANGEPROFILE (access parent file)" fail $subtest $file
runchecktest "CHANGEPROFILE (access sub file)" pass $subtest $subfile

# CHANGEPROFILE TEST -- multiple subprofiles

genprofile $file:$okperm hat:$subtest $subfile:$okperm hat:$subtest2 $subfile:$okperm hat:$subtest3 $subfile:$okperm

runchecktest "CHANGEPROFILE (access parent file)" fail $subtest $file
runchecktest "CHANGEPROFILE (access sub file)" pass $subtest $subfile
runchecktest "CHANGEPROFILE (access sub file)" pass $subtest2 $subfile
runchecktest "CHANGEPROFILE (access sub file)" pass $subtest3 $subfile

