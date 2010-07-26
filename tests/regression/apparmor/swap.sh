#! /bin/bash
# $Id$

#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME swap
#=DESCRIPTION 
# Confined processes are prohibited from executing certain system calls 
# entirely, including swapon(2) swapoff (2).  This test verifies that 
# unconfined processes can call these syscalls but confined processes cannot.
#=END

# I made this a seperate test script because of the need to make a
# swapfile before the tests run.

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

##
## A. SWAP
##

swap_file=$tmpdir/swapfile

dd if=/dev/zero of=${swap_file} bs=1024 count=512 2> /dev/null
/sbin/mkswap ${swap_file} > /dev/null

# TEST 1.  Make sure can enable and disable swap unconfined

runchecktest "SWAPON (unconfined)" pass on ${swap_file}
runchecktest "SWAPOFF (unconfined)" pass off ${swap_file}

# TEST A2.  confine SWAPON

genprofile
runchecktest "SWAPON (confined)" fail on ${swap_file}

# TEST A3.  confine SWAPOFF

/sbin/swapon ${swap_file} 

runchecktest "SWAPOFF (confined)" fail off ${swap_file}

# cleanup, turn off swap

/sbin/swapoff ${swap_file}
