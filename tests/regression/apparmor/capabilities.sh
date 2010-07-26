#!/bin/bash
# $Id$

#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME capabilities
#=DESCRIPTION 
# The capabilities test is an attempt to determine that for a variety of 
# syscalls, the expected capability (especially since Immunix intercepts 
# capability processing for confined processes) and no others allows successful
# access.  For every syscall in the test, we iterate over each capability 
# individually (plus no capabilities) in order to verify that only the expected
# capability grants access to the priviledged operation. The same is repeated 
# for capabilities within hats.
#=END

# An attempt to verify what subdomain/posix capabilities actually grant
# access to. This overlaps _a lot_ with the syscall test.
# this now verifies that a capability functions within a changehat().
# FIXME: should test for a cap in the parent, but the need for the cap
# within the subprofile.  Wow. oogly.

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`
bin=$pwd

. $bin/prologue.inc

TESTS="syscall_ptrace syscall_sethostname \
       syscall_setdomainname syscall_setpriority syscall_setscheduler \
       syscall_reboot syscall_chroot \
       syscall_mlockall net_raw"
# FIXME/XXX - need a test case for syscall_mknod

#only do the ioperm/iopl tests for x86 derived architectures
case `uname -i` in
i386 | i486 | i586 | i686 | x86 | x86_64) 
	TESTS="$TESTS syscall_ioperm syscall_iopl"
	;;
esac

CAPABILITIES="chown dac_override dac_read_search fowner fsetid kill \
	      setgid setuid setpcap linux_immutable net_bind_service \
	      net_broadcast net_admin net_raw ipc_lock ipc_owner \
	      sys_module sys_rawio sys_chroot sys_ptrace sys_pacct \
	      sys_admin sys_boot sys_nice sys_resource sys_time \
	      sys_tty_config mknod lease audit_write audit_control"

# defines which test+capability pairs should succeed.
syscall_reboot_sys_boot=TRUE
syscall_sethostname_sys_admin=TRUE
syscall_setdomainname_sys_admin=TRUE
syscall_setpriority_sys_nice=TRUE
syscall_setscheduler_sys_nice=TRUE
syscall_ioperm_sys_rawio=TRUE
syscall_iopl_sys_rawio=TRUE
syscall_chroot_sys_chroot=TRUE
syscall_mlockall_ipc_lock=TRUE
syscall_sysctl_sys_admin=TRUE
net_raw_net_raw=TRUE

# we completely disable ptrace(), but it's not clear if we should allow it
# when the sys_ptrace cap is specified.
syscall_ptrace_sys_ptrace=TRUE

# if a test case requires arguments, add them here.
syscall_reboot_args=off
syscall_sethostname_args=a.dumb.example.com
syscall_setdomainname_args=dumb.example.com
syscall_ioperm_args="0 0x3ff"
syscall_iopl_args=3
syscall_chroot_args=${tmpdir}/
syscall_ptrace_args=sub

# if a testcase requires extra subdomain rules, add them here
syscall_chroot_extra_entries="/:r ${tmpdir}/:r"
syscall_ptrace_extra_entries="hat:sub"
net_raw_extra_entries="network:"

testwrapper=changehat_wrapper

# needed for modern linux kernels
ulimit -l 0

for TEST in ${TESTS} ; do 
	echo "        (${TEST#syscall_})"
	my_arg=$(eval echo \${${TEST}_args})
	my_entries=$(eval echo \${${TEST}_extra_entries})

	settest ${TEST}
	runchecktest "${TEST} -- unconfined" pass ${my_arg}
	genprofile ${my_entries}
	runchecktest "${TEST} -- no caps" fail ${my_arg}

	# iterate through each of the capabilities
	for cap in ${CAPABILITIES} ; do
		if [ "X$(eval echo \${${TEST}_${cap}})" == "XTRUE" ] ; then
			expected_result=pass
		else
			expected_result=fail
		fi
		genprofile cap:${cap} ${my_entries}
		runchecktest "${TEST} -- capability ${cap}" ${expected_result} ${my_arg}
	done

	# okay, now check to see if the capability functions from within
	# a subprofile.
	# Eww, this is ugly. subprofile tests depend on the internal
	# variable dynlibs defined by prologue.inc::settest
	test_dynlibs=${dynlibs}
	settest ${testwrapper}
	genprofile hat:${TEST} ${test_dynlibs} ${bin}/${TEST}:rix ${my_entries}
	runchecktest "${TEST} changehat -- no caps" fail ${TEST} ${my_arg}
	for cap in ${CAPABILITIES} ; do
		if [ "X$(eval echo \${${TEST}_${cap}})" == "XTRUE" ] ; then
			expected_result=pass
		else
			expected_result=fail
		fi
		genprofile hat:${TEST} ${test_dynlibs} ${bin}/${TEST}:rix cap:${cap} ${my_entries}
		runchecktest "${TEST} changehat -- capability ${cap}" ${expected_result} ${TEST} ${my_arg}
	done

done

