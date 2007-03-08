#! /bin/bash
# $Id$

#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME fd_over_unix
#=DESCRIPTION 
# This tests passing a file descriptor over a unix domain socket.  The server 
# opens a socket, forks a client with it's own profile, passes the file 
# descriptor to it over the socket, and sees what happens.
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

file=${tmpdir}/file
socket=${tmpdir}/unix_fd_test
fd_client=$PWD/unix_fd_client
okperm=rw
badperm=w

# Content generated with:
# dd if=/dev/urandom bs=32 count=4 2> /dev/null | od -x | head -8 | sed -e 's/^[[:xdigit:]]\{7\}//g' -e 's/ //g'
cat > ${file} << EOM
aabcc2739c621194a00b6cb7875dcdeb
72f485a783219817c81c65f3e1b2bc80
4366ba09e881286c834e67b34ae6f186
ccc2c402fcc6e66d5cfaa0c68b94211c
163f7beeb9a320ab859189a82d695713
175797a8cf2e2435dd98551385e96d8f
05f82e8e0e146be0d4655d4681cb08b6
ed15ad1d4fb9959008589e589206ee13
EOM

# lets just be on the safe side
rm -f ${socket}

# PASS - unconfined client

genprofile $file:$okperm $socket:rw $fd_client:ux

runchecktest "fd passing; unconfined client" pass $file $socket $fd_client

sleep 1
rm -f ${socket}

# PASS - confined client, rw access to the file

genprofile $file:$okperm $socket:rw $fd_client:px -- image=$fd_client $file:$okperm $socket:rw
runchecktest "fd passing; confined client w/ rw" pass $file $socket $fd_client

sleep 1
rm -f ${socket}
# FAIL - confined client, w access to the file

genprofile $file:$okperm $socket:rw $fd_client:px -- image=$fd_client $file:$badperm $socket:rw
runchecktest "fd passing; confined client w/ w only" fail $file $socket $fd_client

sleep 1
rm -f ${socket}

