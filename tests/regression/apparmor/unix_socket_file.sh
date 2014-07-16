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

#=NAME unix_socket_file
#=DESCRIPTION
# This tests file access to path-based unix domain sockets. The server
# opens a socket, forks a client with it's own profile, sends a message
# to the client over the socket, and sees what happens.
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc
requires_features policy/versions/v6

client=$bin/unix_socket_file_client
socket=${tmpdir}/unix_socket_file.sock
message=4a0c83d87aaa7afa2baab5df3ee4df630f0046d5bfb7a3080c550b721f401b3b\
8a738e1435a3b77aa6482a70fb51c44f20007221b85541b0184de66344d46a4c
okserver=w
badserver=r

okclient=rw
badclient1=r
badclient2=w

removesocket()
{
	rm -f ${socket}
}

testsocktype()
{
	local socktype=$1 # socket type - stream, dgram, or seqpacket
	local args="$socket $socktype $message $client"

	# PASS - unconfined

	runchecktest "socket file ($socktype); unconfined" pass $args
	removesocket

	# PASS - server w/ access to the file

	genprofile $socket:$okserver $client:Ux
	runchecktest "socket file ($socktype); confined server w/ access ($okserver)" pass $args
	removesocket

	# FAIL - server w/o access to the file

	genprofile $client:Ux
	runchecktest "socket file ($socktype); confined server w/o access" fail $args
	removesocket

	# FAIL - server w/ bad access to the file

	genprofile $socket:$badserver $client:Ux
	runchecktest "socket file ($socktype); confined server w/ bad access ($badserver)" fail $args
	removesocket

	# PASS - client w/ access to the file

	genprofile $socket:$okserver $client:px -- image=$client $socket:$okclient
	runchecktest "socket file ($socktype); confined client w/ access ($okclient)" pass $args
	removesocket

	# FAIL - client w/o access to the file

	genprofile $socket:$okserver $client:px -- image=$client
	runchecktest "socket file ($socktype); confined client w/o access" fail $args
	removesocket

	# FAIL - client w/ bad access to the file

	genprofile $socket:$okserver $client:px -- image=$client $socket:$badclient1
	runchecktest "socket file ($socktype); confined client w/ bad access ($badclient1)" fail $args
	removesocket

	# FAIL - client w/ bad access to the file

	genprofile $socket:$okserver $client:px -- image=$client $socket:$badclient2
	runchecktest "socket file ($socktype); confined client w/ bad access ($badclient2)" fail $args
	removesocket

	removeprofile
}

removesocket
testsocktype stream
testsocktype dgram
testsocktype seqpacket
