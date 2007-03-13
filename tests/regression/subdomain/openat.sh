#! /bin/bash
# $Id$

#	Copyright (C) 2002-2007 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME open
#=DESCRIPTION
# Verify that the openat syscall is correctly managed for confined profiles.
# FIXME: need to add tests that delete the directory after it is opened
# but before the openat() call occurs.
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

subdir=deleteme
file=${subdir}/file
filepath=${tmpdir}/${file}
okperm=rw
badperm1=r
badperm2=w

mkdir ${tmpdir}/${subdir}

# PASS UNCONFINED
runchecktest "OPENAT unconfined RW (create) " pass $tmpdir $file

# PASS TEST (the file shouldn't exist, so open should create it
rm -f ${filepath}
genprofile ${tmpdir}:r ${filepath}:$okperm
runchecktest "OPENAT RW (create) " pass $tmpdir $file

# PASS TEST
genprofile ${tmpdir}:r ${filepath}:$okperm
runchecktest "OPENAT RW" pass $tmpdir $file

# FAILURE TEST (1)
genprofile ${tmpdir}:r ${filepath}:$badperm1
runchecktest "OPENAT R" fail $tmpdir $file

# FAILURE TEST (2)
genprofile ${tmpdir}:r ${filepath}:$badperm2
runchecktest "OPENAT W" fail $tmpdir $file

# FAILURE TEST (3)
genprofile ${tmpdir}:r ${filepath}:$badperm1 cap:dac_override
runchecktest "OPENAT R+dac_override" fail $tmpdir $file

# FAILURE TEST (4)
# This is testing for bug: https://bugs.wirex.com/show_bug.cgi?id=2885
# When we open O_CREAT|O_RDWR, we are (were?) allowing only write access
# to be required.
rm -f ${filepath}
genprofile ${tmpdir}:r ${filepath}:$badperm2
runchecktest "OPENAT W (create)" fail $tmpdir $file
