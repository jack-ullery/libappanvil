#! /bin/bash
#
# Copyright (C) 2014 Canonical, Ltd.
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

#=NAME unix_socket_pathname
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

settest unix_socket

client=$bin/unix_socket_client
sockpath=${tmpdir}/unix_socket.sock
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

# af_unix support requires 'unix create' to call socket()
af_unix=
if [ "$(have_features network/af_unix)" == "true" ] ; then
	af_unix="unix:create"
fi

okclient=rw
badclient1=r
badclient2=w

removesocket()
{
	if [ -S "$1" ]; then
		rm -f "$1"
	fi
}

testsocktype()
{
	local socktype=$1 # stream, dgram, or seqpacket
	local testdesc="AF_UNIX pathname socket ($socktype)"
	local args="$sockpath $socktype $message $client"

	removesocket $sockpath

	# PASS - unconfined

	runchecktest "$testdesc; unconfined" pass $args
	removesocket $sockpath

	# PASS - server w/ access to the file

	genprofile $sockpath:$okserver $af_unix $client:Ux
	runchecktest "$testdesc; confined server w/ access ($okserver)" pass $args
	removesocket $sockpath

	# FAIL - server w/o access to the file

	genprofile $af_unix $client:Ux
	runchecktest "$testdesc; confined server w/o access" fail $args
	removesocket $sockpath

	# FAIL - server w/ bad access to the file

	genprofile $sockpath:$badserver1 $af_unix $client:Ux
	runchecktest "$testdesc; confined server w/ bad access ($badserver1)" fail $args
	removesocket $sockpath

	# $badserver2 is set to non-null at the top of the test script if the
	# kernel advertises ABI v7 or newer
	if [ -n "$badserver2" ] ; then
		# FAIL - server w/ bad access to the file

		genprofile $sockpath:$badserver2 $af_unix $client:Ux
		runchecktest "$testdesc; confined server w/ bad access ($badserver2)" fail $args
		removesocket $sockpath
	fi

	if [ -n "$af_unix" ] ; then
		# FAIL - server w/o af_unix access

		genprofile $sockpath:$okserver $client:Ux
		runchecktest "$testdesc; confined server w/o af_unix" fail $args
		removesocket $sockpath
	fi

	server="$sockpath:$okserver $af_unix $client:px"

	# PASS - client w/ access to the file

	genprofile $server -- image=$client $sockpath:$okclient $af_unix
	runchecktest "$testdesc; confined client w/ access ($okclient)" pass $args
	removesocket $sockpath

	# FAIL - client w/o access to the file

	genprofile $server -- image=$client $af_unix
	runchecktest "$testdesc; confined client w/o access" fail $args
	removesocket $sockpath

	# FAIL - client w/ bad access to the file

	genprofile $server -- image=$client $sockpath:$badclient1 $af_unix
	runchecktest "$testdesc; confined client w/ bad access ($badclient1)" fail $args
	removesocket $sockpath

	# FAIL - client w/ bad access to the file

	genprofile $server -- image=$client $sockpath:$badclient2
	runchecktest "$testdesc; confined client w/ bad access ($badclient2)" fail $args
	removesocket $sockpath

	if [ -n "$af_unix" ] ; then
		# FAIL - client w/o af_unix access

		genprofile $server -- image=$client $sockpath:$okclient
		runchecktest "$testdesc; confined client w/o af_unix" fail $args
		removesocket $sockpath
	fi

	removeprofile
}

for socktype in stream dgram seqpacket; do
	testsocktype "$socktype"
done
