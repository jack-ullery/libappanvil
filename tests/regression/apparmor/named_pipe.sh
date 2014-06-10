#! /bin/bash
#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME named_pipe
#=DESCRIPTION 
# This test verifies that subdomain file access checks function correctly 
# for named piped (nodes in the filesystem created with mknod).  The test 
# creates a parent/child process relationship which attempt to rendevous via 
# the named pipe.   The tests are attempted for unconfined and confined 
# processes and also for subhats.
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

fifo=${tmpdir}/pipe

subtest=sub
okperm=rw

subparent=parent
okparent=r

subchild=child
okchild=w

mknod ${fifo} p

# NAMED PIPE - no confinement 

runchecktest "NAMED PIPE (no confinement)" pass nochange nochange ${fifo}

# PIPE - confined.

#rm -f ${fifo} && mknod ${fifo} p
genprofile $fifo:${okperm}
runchecktest "NAMED PIPE RW (confinement)" pass nochange nochange ${fifo}

# PIPE - confined - no access.

#rm -f ${fifo} && mknod ${fifo} p
genprofile 
runchecktest "NAMED PIPE (confinement)" fail nochange nochange ${fifo}

# PIPE - in a subprofile.

#rm -f ${fifo} && mknod ${fifo} p
genprofile ${fifo}:${okperm} hat:$subtest ${fifo}:${okperm}

runchecktest "NAMED PIPE RW (subprofile)" pass ${subtest} ${subtest} ${fifo}

# PIPE - in a subprofile - no access

#rm -f ${fifo} && mknod ${fifo} p
genprofile ${fifo}:${okperm} hat:$subtest

runchecktest "NAMED PIPE (subprofile)" fail ${subtest} ${subtest} ${fifo}

# PIPE - in separate subprofiles

genprofile hat:$subparent ${fifo}:${okparent} hat:$subchild ${fifo}:${okchild}

runchecktest "NAMED PIPE RW (parent & child subprofiles)" pass ${subparent} ${subchild} ${fifo}

# PIPE - in separate subprofiles - no access for child

genprofile hat:$subparent ${fifo}:${okparent} hat:$subchild

runchecktest "NAMED PIPE R (parent & child subprofiles)" fail ${subparent} ${subchild} ${fifo}

# PIPE - in separate subprofiles - no access for parent

genprofile hat:$subparent hat:$subchild ${fifo}:${okchild}

runchecktest "NAMED PIPE W (parent & child subprofiles)" fail ${subparent} ${subchild} ${fifo}
