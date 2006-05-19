#! /bin/bash
# $Id$

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

subtest=sub
fifo=${tmpdir}/pipe
okperm=rw

mknod ${fifo} p

# NAMED PIPE - no confinement 

runchecktest "NAMED PIPE (no confinement)" pass nochange ${fifo}

# PIPE - confined.

#rm -f ${fifo} && mknod ${fifo} p
genprofile $fifo:${okperm}
runchecktest "NAMED PIPE RW (confinement)" pass nochange ${fifo}

# PIPE - confined - no access.

#rm -f ${fifo} && mknod ${fifo} p
genprofile 
runchecktest "NAMED PIPE (confinement)" fail nochange ${fifo}

# PIPE - in a subprofile.

#rm -f ${fifo} && mknod ${fifo} p
genprofile ${fifo}:${okperm} hat:$subtest ${fifo}:${okperm}

runchecktest "NAMED PIPE RW (subprofile)" pass ${subtest} ${fifo}

# PIPE - in a subprofile - no access

#rm -f ${fifo} && mknod ${fifo} p
genprofile ${fifo}:${okperm} hat:$subtest

runchecktest "NAMED PIPE (subprofile)" fail ${subtest} ${fifo}
