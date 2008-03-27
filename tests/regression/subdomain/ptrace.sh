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

# Read permission was required for a confined process to be able to be traced 
# using ptrace.  This stopped being required or functioning correctly 
# somewhere between 2.4.18 and 2.4.20.
#

helper=$pwd/ptrace_helper

# test base line of unconfined tracing unconfined
runchecktest "test 1" pass -n 100 /bin/true
runchecktest "test 1 -c" pass -c -n 100 /bin/true
runchecktest "test 1 -h" pass -h -n 100 $helper
runchecktest "test 1 -hc" pass -h -c -n 100 $helper
runchecktest "test 1 -h prog" pass -h -n 100 $helper /bin/true
runchecktest "test 1 -hc prog" pass -h -c -n 100 $helper /bin/true

# test that unconfined can ptrace before profile attaches
genprofile image=/bin/true
runchecktest "test 2" pass -n 100 /bin/true
runchecktest "test 2 -c" pass -c -n 100 /bin/true
runchecktest "test 2 -h" pass -h -n 100 $helper
runchecktest "test 2 -hc" pass -h -c -n 100 $helper
runchecktest "test 2 -h prog" pass -h -n 100 $helper /bin/true
runchecktest "test 2 -hc prog" pass -h -c -n 100 $helper /bin/true

#unconfined tracing confined helper
#confined helper asking unconfined process to ptrace it
genprofile image=$helper
runchecktest "test 3 -h" pass -h -n 100 $helper
runchecktest "test 3 -hc " pass -h -c -n 100 $helper
# can't exec /bin/true so fail
runchecktest "test 3 -h prog" fail -h -n 100 $helper /bin/true
runchecktest "test 3 -hc prog" fail -h -c -n 100 $helper /bin/true

# lack of 'r' perm is currently not working
genprofile image=$helper $helper:ix
runchecktest "test 4 -h" pass -h -n 100 $helper
runchecktest "test 4 -hc " pass -h -c -n 100 $helper
# can't exec /bin/true so fail
runchecktest "test 4 -h prog" fail -h -n 100 $helper /bin/true
runchecktest "test 4 -hc prog" fail -h -c -n 100 $helper /bin/true

genprofile image=$helper $helper:rix
runchecktest "test 5 -h" pass -h -n 100 $helper
runchecktest "test 5 -hc " pass -h -c -n 100 $helper
# can't exec /bin/true so fail
runchecktest "test 5 -h prog" fail -h -n 100 $helper /bin/true
runchecktest "test 5 -hc prog" fail -h -c -n 100 $helper /bin/true

genprofile image=$helper $helper:ix /bin/true:rix
runchecktest "test 6 -h" pass -h -n 100 $helper
runchecktest "test 6 -hc " pass -h -c -n 100 $helper
runchecktest "test 6 -h prog" pass -h -n 100 $helper /bin/true
runchecktest "test 6 -hc prog" pass -h -c -n 100 $helper /bin/true

#traced child can ptrace_me to unconfined have unconfined trace them
genprofile image=/bin/true
runchecktest "test 7" pass -n 100 /bin/true
# pass - ptrace_attach is done in unconfined helper
runchecktest "test 7 -c " pass -c -n 100 /bin/true
runchecktest "test 7 -h" pass -h -n 100 $helper
# pass - ptrace_attach is done in unconfined helper
runchecktest "test 7 -hc " pass -h -c -n 100 $helper
runchecktest "test 7 -h prog" pass -h -n 100 $helper /bin/true
runchecktest "test 7 -hc prog" pass -h -c -n 100 $helper /bin/true

genprofile image=$helper $helper:ix /bin/true:rix
runchecktest "test 7a" pass -n 100 /bin/true
# pass - ptrace_attach is allowed from confined process to unconfined
runchecktest "test 7a -c " pass -c -n 100 /bin/true
runchecktest "test 7a -h" pass -h -n 100 $helper
# pass - ptrace_attach is allowed from confined process to unconfined
runchecktest "test 7a -hc " pass -h -c -n 100 $helper
runchecktest "test 7a -h prog" pass -h -n 100 $helper /bin/true
runchecktest "test 7a -hc prog" pass -h -c -n 100 $helper /bin/true

#traced helper can't do px - should update so depends on tracer
genprofile image=$helper $helper:ix /bin/true:rpx -- image=/bin/true
runchecktest "test 8" pass -n 100 /bin/true
# pass - ptrace_attach is done before exec
runchecktest "test 8 -c " pass -c -n 100 /bin/true
runchecktest "test 8 -h" pass -h -n 100 $helper
runchecktest "test 8 -hc " pass -h -c -n 100 $helper
# fail - can not px due to ptrace
runchecktest "test 8 -h prog" fail -h -n 100 $helper /bin/true
runchecktest "test 8 -hc prog" fail -h -c -n 100 $helper /bin/true

#traced helper can't do ux - should update so depends on tracer
genprofile image=$helper $helper:ix /bin/true:rux -- image=/bin/true
runchecktest "test 9" pass -n 100 /bin/true
# pass - ptrace_attach is done before exec
runchecktest "test 9 -c " pass -c -n 100 /bin/true
runchecktest "test 9 -h" pass -h -n 100 $helper
runchecktest "test 9 -hc " pass -h -c -n 100 $helper
# fail - can not ux due to ptrace
runchecktest "test 9 -h prog" fail -h -n 100 $helper /bin/true
runchecktest "test 9 -hc prog" fail -h -c -n 100 $helper /bin/true

genprofile
# fail due to no exec permission
runchecktest "test 10" fail -n 100 /bin/true
runchecktest "test 10 -c" fail -c -n 100 /bin/true
runchecktest "test 10 -h" fail -h -n 100 $helper
runchecktest "test 10 -hc" fail -h -c -n 100 $helper
runchecktest "test 10 -h prog" fail -h -n 100 $helper /bin/true
runchecktest "test 10 -hc prog" fail -h -c -n 100 $helper /bin/true

genprofile /bin/true:ix $helper:ix
# fail due to missing r permission
#runchecktest "test 11" fail -n 100 /bin/true
#runchecktest "test 11 -c" fail -c -n 100 /bin/true
#runchecktest "test 11 -h" fail -h -n 100 $helper
#runchecktest "test 11 -hc" fail -h -c -n 100 $helper
#runchecktest "test 11 -h prog" fail -h -n 100 $helper /bin/true
#runchecktest "test 11 -hc prog" fail -h -c -n 100 $helper /bin/true

# pass allowed to ix self
genprofile /bin/true:rix $helper:rix
runchecktest "test 12" pass -n 100 /bin/true
runchecktest "test 12 -c" pass -c -n 100 /bin/true
runchecktest "test 12 -h" pass -h -n 100 $helper
runchecktest "test 12 -hc" pass -h -c -n 100 $helper
runchecktest "test 12 -h prog" pass -h -n 100 $helper /bin/true
runchecktest "test 12 -hc prog" pass -h -c -n 100 $helper /bin/true

#ptraced confined app can't px - fails to unset profile
genprofile image=$helper $helper:rix /bin/true:rpx
runchecktest "test 14 -h prog" fail -h -n 100 $helper /bin/true
runchecktest "test 14 -hc prog" fail -h -c -n 100 $helper /bin/true

#ptraced confined app can't ux - fails to unset profile
genprofile image=$helper $helper:rix /bin/true:rux
runchecktest "test 14 -h prog" fail -h -n 100 $helper /bin/true
runchecktest "test 14 -hc prog" fail -h -c -n 100 $helper /bin/true

#confined app can't ptrace an unconfined app
genprofile $helper:rux
runchecktest "test 15 -h" fail -h -n 100 $helper
runchecktest "test 15 -h prog" fail -h -n 100 $helper /bin/true
#an unconfined app can't ask a confined app to trace it
runchecktest "test 15 -hc" fail -h -c -n 100 $helper
runchecktest "test 15 -hc prog" fail -h -c -n 100 $helper /bin/true

#confined app can't ptrace an app confined by a different profile
genprofile $helper:rpx -- image=$helper
runchecktest "test 15 -h" fail -h -n 100 $helper
runchecktest "test 15 -h prog" fail -h -n 100 $helper /bin/true
#a confined app can't ask another confined app with a different profile to
#trace it
runchecktest "test 15 -hc" fail -h -c -n 100 $helper
runchecktest "test 15 -hc prog" fail -h -c -n 100 $helper /bin/true




# need to do a confined process trying to attach to an unconfined
# need attaching, and ptrace_me of different confinement
