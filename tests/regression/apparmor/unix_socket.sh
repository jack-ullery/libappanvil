#! /bin/bash
#
# Copyright (C) 2013 Canonical, Ltd.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public
# License published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, contact Canonical Ltd.

#=NAME unix_socket
#=DESCRIPTION
# This tests file access to unix domain sockets. The server opens a socket,
# forks a client with it's own profile, sends a message to the client over the
# socket, and sees what happens.
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc
requires_features policy/versions/v6

client=$bin/unix_socket_client
sockpath_pathname=${tmpdir}/unix_socket.sock
sockpath_abstract="@apparmor_unix_socket"
message=4a0c83d87aaa7afa2baab5df3ee4df630f0046d5bfb7a3080c550b721f401b3b\
8a738e1435a3b77aa6482a70fb51c44f20007221b85541b0184de66344d46a4c

# v6 requires 'w' and v7 requires 'rw'
okserver=w
badserver1=r
badserver2=
if [ "$(have_features policy/versions/v7)" == "true" ] ; then
	okserver=rw
	badserver2=w
fi

okclient=rw
badclient1=r
badclient2=w

isabstract()
{
	[ "${1:0:1}" == "@" ]
}

removesocket()
{
	if ! isabstract "$1"; then
		rm -f "$1"
	fi
}

testsocktype()
{
	local testdesc=$1 # description (eg, "AF_UNIX abstract socket (dgram)")
	local sockpath=$2 # fs path or "@NAME" for an abstract sock
	local socktype=$3 # stream, dgram, or seqpacket
	local args="$sockpath $socktype $message $client"

	removesocket $sockpath

	# PASS - unconfined

	runchecktest "$testdesc; unconfined" pass $args
	removesocket $sockpath

	# TODO: Make additional changes to test abstract sockets w/ confinement
	#
	#  * Adjust genprofile to generate af_unix abstract socket rules
	#  * Create variables to hold genprofile arguments for socket accesses
	#    and initialize them according to socket address type
	#  * Remove the following conditional
	if isabstract $sockpath; then
		return
	fi

	# PASS - server w/ access to the file

	genprofile $sockpath:$okserver $client:Ux
	runchecktest "$testdesc; confined server w/ access ($okserver)" pass $args
	removesocket $sockpath

	# FAIL - server w/o access to the file

	genprofile $client:Ux
	runchecktest "$testdesc; confined server w/o access" fail $args
	removesocket $sockpath

	# FAIL - server w/ bad access to the file

	genprofile $sockpath:$badserver1 $client:Ux
	runchecktest "$testdesc; confined server w/ bad access ($badserver1)" fail $args
	removesocket $sockpath

	# $badserver2 is set to non-null at the top of the test script if the
	# kernel advertises ABI v7 or newer
	if [ -n "$badserver2" ] ; then
		# FAIL - server w/ bad access to the file

		genprofile $sockpath:$badserver2 $client:Ux
		runchecktest "$testdesc; confined server w/ bad access ($badserver2)" fail $args
		removesocket $sockpath
	fi

	# PASS - client w/ access to the file

	genprofile $sockpath:$okserver $client:px -- image=$client $sockpath:$okclient
	runchecktest "$testdesc; confined client w/ access ($okclient)" pass $args
	removesocket $sockpath

	# FAIL - client w/o access to the file

	genprofile $sockpath:$okserver $client:px -- image=$client
	runchecktest "$testdesc; confined client w/o access" fail $args
	removesocket $sockpath

	# FAIL - client w/ bad access to the file

	genprofile $sockpath:$okserver $client:px -- image=$client $sockpath:$badclient1
	runchecktest "$testdesc; confined client w/ bad access ($badclient1)" fail $args
	removesocket $sockpath

	# FAIL - client w/ bad access to the file

	genprofile $sockpath:$okserver $client:px -- image=$client $sockpath:$badclient2
	runchecktest "$testdesc; confined client w/ bad access ($badclient2)" fail $args
	removesocket $sockpath

	removeprofile
}

testsockpath()
{
	local sockpath="$1" # $sockpath_pathname or $sockpath_abstract
	local testdesc="AF_UNIX "
	local socktype=

	if [ "$sockpath" == "$sockpath_pathname" ]; then
		testdesc+="pathname socket"
	elif [ "$sockpath" == "$sockpath_abstract" ]; then
		testdesc+="abstract socket"
	else
		fatalerror "Unknown sockpath addr type: $sockpath"
	fi

	for socktype in stream dgram seqpacket; do
		testsocktype "$testdesc ($socktype)" "$sockpath" "$socktype"
	done
}

testsockpath "$sockpath_pathname"
testsockpath "$sockpath_abstract"
# TODO: testsockpath "$sockpath_unnamed"
#
#  * Adjust unix_socket.c and unix_socket_client.c when the socket path is
#    "UNNAMED"
#    - Don't bind() the socket
#    - Don't set SO_CLOEXEC so that the fd can be passed over exec()
#  * Decide how to generate appropriate access rules (if any are needed)
#  * Define sockpath_unnamed as "UNNAMED"
#  * Update testsockpath() to handle sockpath_unnamed
#  * Create isunnamed() and update removesocket() to call it
