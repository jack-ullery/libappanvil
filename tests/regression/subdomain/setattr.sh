#! /bin/bash
# $Id$

#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME setattr
#=DESCRIPTION
# Write permission is required in a confined processes profile in order to
# change the mode (chmod, chgrp, chown) of a file.  This test verifies these
# system calls for unconfined and confined processes. It also includes
# the fxxx version of the tests.
#=END

checkfile()
{
	_file=$1
	_str=$2
	_newfileperm=$3
	_newuser=$4
	_newgroup=$5

	set -- `ls -l $_file`

	if [ $1 != "$_newfileperm" -o $3 != $_newuser -o $4 != $_newgroup ]
	then
		echo "Error: ($_str)"
		echo "Error: ls -l $file output does not look correct"
		echo "Error: saw: $1/$3/$4   expected: $_newfileperm/$_newuser/$_newgroup"
	fi
}

resettest()
{
	rm -f $file
	touch $file
	chmod $origfileperm $file
}

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

file=$tmpdir/file

okperm=rw
badperm=r

pwfiles="/etc/passwd:r /etc/group:r"

origfileperm=644
origfilepermstr="-rw-r--r--"
newfileperm=400
newfilepermstr="-r--------"
origuser=`id -un`
newuser=nobody
newuid=$(awk -F: "/^${newuser}:/ {print \$3}" /etc/passwd)
origgroup=`id -gn`
# Sigh, debian uses group nogroup instead of nobody
# XXX - not sure what to do if neither exist.
if [ $(grep -c nobody /etc/group) -gt 0 ] ; then
	newgroup=nobody
elif [ $(grep -c nogroup /etc/group) -gt 0 ] ; then
	newgroup=nogroup
else 
	newgroup=bin
fi
newgid=$(awk -F: "/^${newgroup}:/ {print \$3}" /etc/group)
#echo newuser=${newuser} newuid=${newuid}
#echo newgroup=${newgroup} newgid=${newgid}


# NOTE on the ordering of tests: XFS requires the FOWNER capability
# to chgrp a file that you are not the owner of; linux's vfs layer will
# allow you to do it if you are in the group of the file without FOWNER.
# Therefore, we should do the chgrp test BEFORE changing the owner of
# the file.

# PASS TEST (UNCONFINED)
resettest

settest chmod
runchecktest "CHMOD (unconfined)" pass $file $newfileperm

settest chgrp
runchecktest "CHGRP (unconfined)" pass $file $newgid

settest chown
runchecktest "CHOWN (unconfined)" pass $file $newuid

checkfile $file "unconfined" $newfilepermstr $newuser $newgroup

# PASS TEST (UNCONFINED w/FOPS)
resettest

settest fchmod
runchecktest "FCHMOD (unconfined)" pass $file $newfileperm

settest fchgrp
runchecktest "FCHGRP (unconfined)" pass $file $newgid

settest fchown
runchecktest "FCHOWN (unconfined)" pass $file $newuid

checkfile $file "unconfined" $newfilepermstr $newuser $newgroup

# PASS TEST (CONFINED)
resettest

settest chmod
genprofile $file:$okperm 
runchecktest "CHMOD (confined $okperm)" pass $file $newfileperm

settest chgrp
genprofile $file:$okperm $pwfiles cap:chown
runchecktest "CHGRP (confined $okperm)" pass $file $newgid

settest chown
genprofile $file:$okperm $pwfiles cap:chown
runchecktest "CHOWN (confined $okperm)" pass $file $newuid

checkfile $file "confined $okperm" $newfilepermstr $newuser $newgroup

# PASS TEST (CONFINED w/FOPS)
resettest

settest fchmod
genprofile $file:$okperm 
runchecktest "FCHMOD (confined $okperm)" pass $file $newfileperm

settest fchgrp
genprofile $file:$okperm $pwfiles cap:chown
runchecktest "FCHGRP (confined $okperm)" pass $file $newgid

settest fchown
genprofile $file:$okperm $pwfiles cap:chown
runchecktest "FCHOWN (confined $okperm)" pass $file $newuid

checkfile $file "confined $okperm" $newfilepermstr $newuser $newgroup

# FAIL TEST (CONFINED)
resettest

settest chmod
genprofile $file:$badperm $pwfiles
runchecktest "CHMOD (confined $badperm)" fail $file $newfileperm

settest chgrp
genprofile $file:$badperm $pwfiles cap:chown
runchecktest "CHGRP (confined $badperm)" fail $file $newgid

settest chown
genprofile $file:$badperm $pwfiles cap:chown
runchecktest "CHOWN (confined $badperm)" fail $file $newuid

checkfile $file "confined $badperm" $origfilepermstr $origuser $origgroup

# FAIL TEST (CONFINED/LACKING CAPS)
resettest

settest chgrp
genprofile $file:$okperm $pwfiles
runchecktest "CHGRP (confined $okperm/no capabilities)" fail $file $newgid

settest chown
genprofile $file:$okperm $pwfiles
runchecktest "CHOWN (confined $okperm/no capabilities)" fail $file $newuid

checkfile $file "confined $badperm" $origfilepermstr $origuser $origgroup

# FAIL TEST (CONFINED w/FOPS)
resettest

settest fchmod
genprofile $file:$badperm $pwfiles
runchecktest "FCHMOD (confined $badperm)" fail $file $newfileperm

settest fchgrp
genprofile $file:$badperm $pwfiles cap:chown
runchecktest "FCHGRP (confined $badperm)" fail $file $newgid

settest fchown
genprofile $file:$badperm $pwfiles cap:chown
runchecktest "FCHOWN (confined $badperm)" fail $file $newuid

checkfile $file "confined $badperm" $origfilepermstr $origuser $origgroup

# FAIL TEST (CONFINED w/FOPS/LACKING CAPS)
resettest

settest fchgrp
genprofile $file:$okperm $pwfiles
runchecktest "FCHGRP (confined $okperm/no capabilities)" fail $file $newgid

settest fchown
genprofile $file:$okperm $pwfiles
runchecktest "FCHOWN (confined $okperm/no capabilities)" fail $file $newuid

checkfile $file "confined $badperm" $origfilepermstr $origuser $origgroup
