#! /bin/bash
#	Copyright (C) 2022 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME nfs
#=DESCRIPTION 
# This test verifies that file access on a mounted NFS share is determined
# by file rules and not network rules.
# https://bugs.launchpad.net/ubuntu/+source/apparmor/+bug/1784499
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

srcdir=$tmpdir/src
mntdir=$tmpdir/mnt
file1=$mntdir/file1
file2=$mntdir/file2
file3=$mntdir/file3
file4=$mntdir/file4
newdir=$mntdir/dir/
exportline="$srcdir localhost(rw,sync,no_subtree_check)"
fileperm=rw
dirperm=w
nfsport1=111
nfsport2=2049

cleanup_nfs()
{
	umount -fq "$mntdir"
	sed -i "\|^$srcdir|d" "/etc/exports" 2>/dev/null
	exportfs -ar >/dev/null 2>&1
}

# Skip this test if NFS server is not available
nfs_not_available()
{
	echo "NFS server not available. Skipping tests ..."
	exit 0
}

do_onexit="cleanup_nfs"
mkdir -p $srcdir
chmod 777 $srcdir
mkdir -p $mntdir

# Export and mount directory over NFS
systemctl --quiet is-active nfs-server || nfs_not_available
echo "$exportline" >> "/etc/exports"
exportfs -ar || nfs_not_available
mount "localhost:$srcdir" "$mntdir" || nfs_not_available

settest open

# PASS TEST
# Caching can cause this test to pass even on kernels where the nfs bug is
# present.
genprofile $file1:$fileperm
runchecktest "OPEN RW (nfs file create) " xpass $file1

# PASS TEST
# Dropping caches should only pass on kernels where the nfs bug has been fixed.
genprofile $file2:$fileperm
sync; echo 3 > /proc/sys/vm/drop_caches
runchecktest "OPEN RW (nfs file create after cache drop) " xpass $file2

if [ "$(kernel_features network)" == "true" -o \
	   "$(kernel_features network_v8)" == "true" ]; then
	# PASS TEST
	# Allowing network streams and file access should pass regardless
	genprofile "network:inet stream" $file3:$fileperm
	sync; echo 3 > /proc/sys/vm/drop_caches
	runchecktest "OPEN RW (nfs file create with net permissions) " pass $file3

	# FAIL TEST
	# Allowing only network streams should fail regardless
	genprofile "network:inet stream"
	sync; echo 3 > /proc/sys/vm/drop_caches
	runchecktest "OPEN RW (nfs file create with net permissions without file permissions) " fail $file4
fi

# PASS TEST
# Verify directory creation behaves as expected over nfs
settest mkdir
genprofile $newdir:$dirperm
sync; echo 3 > /proc/sys/vm/drop_caches
runchecktest "MKDIR (nfs confined)" xpass mkdir $newdir
