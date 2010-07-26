#! /bin/bash
# $Id$

#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME coredump
#=DESCRIPTION coredump test

checkcorefile()
{
_corefilelist=`echo core.*`
if [ "$_corefilelist" = "core.*" ]
then
	_corefile=no
else
	_corefile=yes
fi

if [ "$1" = "yes" -a "$_corefile" = "no" ]
then
	echo "Error: corefile expected but not present - $2"
elif [ "$1" = "no" -a "$_corefile"  = "yes" ]
then
	echo "Error: corefile present when not expected -- $2"
fi

unset _corefile _corefilelist
rm -f core.*
}

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

coreperm=r
nocoreperm=ix

# enable coredumps
ulimit -c 1000000

# PASS TEST, no confinement
echo "*** A 'Segmentation Fault' message from bash is expected for the following test"
runchecktest "COREDUMP (no confinement)" signal11
checkcorefile yes "COREDUMP (no confinement)"

# PASS TEST, with r confinement
genprofile $test:$coreperm
cat $profile

echo
echo "*** A 'Segmentation Fault' message from bash is expected for the following test"
runchecktest "COREDUMP ($coreperm confinement)" signal11
checkcorefile yes "COREDUMP ($coreperm confinement)"

# FAIL TEST, with x confinement
genprofile $test:$nocoreperm
cat $profile

echo
echo "*** A 'Segmentation Fault' message from bash is expected for the following test"
runchecktest "COREDUMP ($nocoreperm confinement)" signal11
checkcorefile no "COREDUMP ($nocoreperm confinement)"
