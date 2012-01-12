#! /bin/bash
#	Copyright (C) 2002-2005 Novell/SUSE
#	Copyright (C) 2010 Canonical, Ltd
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME coredump
#=DESCRIPTION coredump test

cleancorefile()
{
	rm -f core core.*
}

checkcorefile()
{
	# global _testdesc _pfmode _known outfile
	if [ ${1:0:1} == "x" ] ; then
		requirement=${1#x}
		_known=" (known problem)"
        else
		requirement=$1
		_known=""
        fi

	_corefilelist=`echo core.*`
	if [ ! -f core ] && [ "$_corefilelist" = "core.*" ]
	then
		_corefile=no
	else
		_corefile=yes
	fi

	if [ "$requirement" = "yes" -a "$_corefile" = "no" ] ; then
		if [ -n $_known ] ; then
			echo -n "XFAIL: "
		fi
		echo "Error: corefile expected but not present - $2"
		if [ -z $_known ] ; then
			cat $profile
			testfailed
		fi
	elif [ "$requirement" = "no" -a "$_corefile"  = "yes" ] ; then
		if [ -n "$_known" ] ; then
			echo -n "XFAIL: "
		fi
		echo "Error: corefile present when not expected -- $2"
		if [ -z "$_known" ] ; then
			cat $profile
			testfailed
		fi
	fi

	unset _corefile _corefilelist
	cleancorefile
}

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

coreperm=r
nocoreperm=ix

# enable coredumps
ulimit -c 1000000
cleancorefile
checkcorefile no "COREDUMP (starting with clean slate)"

# PASS TEST, no confinement
cleancorefile
echo "*** A 'Segmentation Fault' message from bash is expected for the following test"
runchecktest "COREDUMP (no confinement)" signal11
checkcorefile yes "COREDUMP (no confinement)"

# PASS TEST, with r confinement
cleancorefile
genprofile -I $test:$coreperm

echo
echo "*** A 'Segmentation Fault' message from bash is expected for the following test"
runchecktest "COREDUMP ($coreperm confinement)" signal11
checkcorefile yes "COREDUMP ($coreperm confinement)"

# FAIL TEST, with x confinement
cleancorefile
genprofile -I $test:$nocoreperm

echo
echo "*** A 'Segmentation Fault' message from bash is expected for the following test"
runchecktest "COREDUMP ($nocoreperm confinement)" signal11
checkcorefile xno "COREDUMP ($nocoreperm confinement)"
