#! /bin/bash
# $Id$

#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME ptrace
#=DESCRIPTION 
# Verify ptrace.  The tracing process (attacher or parent of ptrace_me) may 
# not be confined.
# 
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

# Disabled tests:
# Tests 3b and 4b
# Read permission was required for a confined process to be able to be traced 
# using ptrace.  This stopped being required or functioning correctly 
# somewhere between 2.4.18 and 2.4.20.
#

# Test Matrix:
# 1. unconfined parent, unconfined child, parent attaches		PASS
# 2. unconfined parent, unconfined child, child requests tracing	PASS
# 3a. unconfined parent, confined child (r), parent attaches		PASS
# 4a. unconfined parent, confined child (r), child requests tracing	PASS
# 3b. unconfined parent, confined child (!r), parent attaches		FAIL
# 4b. unconfined parent, confined child (!r), child requests tracing	FAIL
# 5. confined parent, unconfined child, parent attaches			FAIL
# 6. confined parent, unconfined child, child requests tracing		FAIL
# 7. confined parent, confined child, parent attaches			FAIL
# 8. confined parent, confined child, child requests tracing		FAIL
# 9. unconfined traced task attempts exec				PASS
# 10. confined traced task attempts exec unconfined			FAIL
# 11. confined traced task attempts exec confined			FAIL

helper=$pwd/ptrace_helper

runchecktest "test 1" pass -n 100 /bin/true
runchecktest "test 2" pass -c -n 100 /bin/true

genprofile image=$helper
runchecktest "test 3a" pass -h -n 100 $helper
runchecktest "test 4a" pass -h -n 100 -c $helper

# lack of 'r' perm is currently not working
genprofile image=ix$helper
runchecktest "test 3b" pass -h -n 100 $helper
runchecktest "test 4b" pass -h -n 100 -c $helper

genprofile $helper:ux
runchecktest "test 5" fail -h -n 100 $helper
runchecktest "test 6" fail -h -n 100 -c $helper

genprofile $helper:px -- image=$helper
runchecktest "test 7" fail -h -n 100 $helper
runchecktest "test 8" fail -h -n 100 -c $helper

genprofile image=/bin/true
runchecktest "test 9" pass -- /bin/bash -c /bin/true

genprofile image=$helper /bin/true:ux
runchecktest "test 10" fail -h -n 100 $helper /bin/true

genprofile image=$helper /bin/true:rix
runchecktest "test 11" fail -h -n 2000 $helper /bin/true
