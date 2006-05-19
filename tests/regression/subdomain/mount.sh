#! /bin/bash
# $Id$

#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME mount
#=DESCRIPTION 
# This test verifies that the mount syscall is indeed restricted for confined 
# processes.
#=END

# I made this a seperate test script because of the need to make a
# loopfile before the tests run.

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

##
## A. MOUNT
##

mount_file=$tmpdir/mountfile
mount_point=$tmpdir/mountpoint
loop_device="unset" 

dd if=/dev/zero of=${mount_file} bs=1024 count=512 2> /dev/null
/sbin/mkfs -text2 -F ${mount_file} > /dev/null 2> /dev/null
/bin/mkdir ${mount_point}

# in a modular udev world, the devices won't exist until the loopback
# module is loaded.
if [ ! -b /dev/loop0 ] ; then 
	modprobe loop
fi

# kinda ugly way of atomically finding a free loop device
for i in $(seq 0 15) 
do
	if [ "$loop_device" = "unset" ] 
	then
		if /sbin/losetup /dev/loop$i ${mount_file} > /dev/null 2> /dev/null
		then 
			loop_device=/dev/loop$i;
		fi
	fi
done
if [ "$loop_device" = "unset" ] 
then
	fatalerror 'Unable to find a free loop device'
fi

# TEST 1.  Make sure can mount and umount unconfined

runchecktest "MOUNT (unconfined)" pass mount ${loop_device} ${mount_point}
runchecktest "UMOUNT (unconfined)" pass umount ${loop_device} ${mount_point}

# TEST A2.  confine MOUNT

genprofile capability:sys_admin
runchecktest "MOUNT (confined)" fail mount ${loop_device} ${mount_point}

# TEST A3.  confine UMOUNT

/bin/mount -text2 ${loop_device} ${mount_point}

runchecktest "UMOUNT (confined)" fail umount ${loop_device} ${mount_point}

# cleanup, umount file
/bin/umount ${loop_device} > /dev/null 2> /dev/null  || /sbin/losetup -d ${loop_device} > /dev/null 2> /dev/null

/sbin/losetup -d ${loop_device} > /dev/null 2> /dev/null
