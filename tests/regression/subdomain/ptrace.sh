#! /bin/bash
# $Id: ptrace.sh 6040 2006-01-11 00:15:48Z tonyj $

#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME ptrace
#=DESCRIPTION 
# Read permission is required for a confined process to be able to be traced 
# using ptrace.  This test verifies this.  Currently is it not functioning 
# correctly. It stopped functioning correctly somewhere between 2.4.18 and 
# 2.4.20.
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

file=$tmpdir/file
traceperm=rix
notraceperm=ix
openperm=rw

touch $file

# PASS TEST, no confinement
settest open

runchecktest "STRACE OPEN (no confinement)" pass $file

# PASS TEST, with rx confinement
settest open "$bin/strace.sh {}"
genprofile $test:$traceperm $file:$openperm

runchecktest "STRACE OPEN ($traceperm confinement)" pass $file

# FAIL TEST, with x confinement
settest open "$bin/strace.sh {}"
genprofile $test:$notraceperm $file:$openperm

runchecktest "STRACE OPEN ($notraceperm confinement)" fail $file
