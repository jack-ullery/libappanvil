#! /bin/bash
# $Id: rename.sh 6040 2006-01-11 00:15:48Z tonyj $

#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME rename
#=DESCRIPTION 
# The rename system call changes the name of a file in the filesystem.  The 
# test verifies that this operation (which involves AppArmor write and link 
# permission checks) functions correctly for a confined process.
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

file1=$tmpdir/file1
file2=$tmpdir/file2

okfile1perm=rwl
badfile1perm1=r
badfile1perm2=w
okfile2perm=w
badfile2perm=r

# PASS TEST

touch $file1 
chmod 600 $file1

genprofile $file1:$okfile1perm $file2:$okfile2perm

runchecktest "RENAME RWL W" pass $file1 $file2

# FAILURE TEST (1) - Bad permissions on target

touch $file1 
chmod 600 $file1

genprofile $file1:$okfile1perm $file2:$badfile2perm

runchecktest "RENAME RWL R" fail $file1 $file2

# FAILURE TEST (2) - no permissions on target

touch $file1 
chmod 600 $file1

genprofile $file1:$okfile1perm

runchecktest "RENAME RWL -" fail $file1 $file2

# FAILURE TEST (3) - Bad permissions on source

touch $file1 
chmod 600 $file1

genprofile $file1:$badfile1perm1 $file2:$okfile2perm

runchecktest "RENAME R W" fail $file1 $file2

# FAILURE TEST (4) - Bad permissions on source

touch $file1 
chmod 600 $file1

genprofile $file1:$badfile1perm2 $file2:$okfile2perm

runchecktest "RENAME W W" fail $file1 $file2

# FAILURE TEST (5) - No permissions on source

touch $file1 
chmod 600 $file1

genprofile $file2:$okfile2perm

runchecktest "RENAME - W" fail $file1 $file2
