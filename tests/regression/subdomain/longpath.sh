#! /bin/bash
# $Id$

#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME longpath
#=DESCRIPTION 
# Verify handling of long pathnames.
#=END

genrandname()
{
	_goal=$1
	_ascii="abcdefghijlkmnopqrstuvwxyz0123456789"
	_mod=${#_ascii}
	_i=0

	for _i in `seq 2 $_goal`
	do
		_c=$((RANDOM % $_mod))
		_s="${_s}${_ascii:$_c:1}"
	done

	echo $_s
}
pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

name_max=255 #NAME_MAX
direlem_max=235 #Length for intermediate dirs, slightly less than name_max
buf_max=4096 #PAGE

# generate 255 character filename
file=`genrandname $name_max`
file2=`genrandname $name_max`

settest open
okperm=rw
linkperm=rwl

cd $tmpdir

mkdir_expected_fail=0
file_expected_fail=0
link_expected_fail=0

iter=1
while true
do
	direlem=`genrandname $direlem_max`

	_dpath=`pwd`/$direlem

	if [ ${#_dpath} -lt 4096 ]
	then
		dstatus=pass
	else
		dstatus=fail
	fi

	settest mkdir
	genprofile $tmpdir/**:$okperm
	runchecktest "LONGPATH MKDIR ($iter)" $dstatus mkdir $direlem

	if [ $dstatus = "pass" ]
	then
		if [ -d $direlem ]
		then
			#echo "mkdir ($iter) passed at length ${#_dpath}"
			cd $direlem
		else
			echo "FAIL: $direlem ($_iter) was not created" >&2
		fi
	else
		if [ -d $direlem ]
		then
			echo "mkdir ($iter) incorrectly generated dir at length ${#_dpath}"
		else
			#echo "mkdir ($iter) failed at length ${#_dpath}"
			mkdir_expected_fail=1
		fi
		:
	fi

	_fpath=`pwd`/$file
	if [ ${#_fpath} -lt 4096 ]
	then
		fstatus=pass
	else
		fstatus=fail
	fi

	settest open
	genprofile $tmpdir/**:$okperm
	runchecktest "LONGPATH CREATE ($iter)" $fstatus $file
	
	if [ $fstatus = "pass" ]
	then
		if [ -f $file ]
		then
			#echo "file creat ($iter) passed at length ${#_dpath}"
			:
		else
			echo "FAIL: $file ($_iter) was not created" >&2
		fi
	elif [ $fstatus = "fail" ]
	then
		if [ -f $file ]
		then
			echo "file creat ($iter) incorrectly generated file at length ${#_fpath}"
		else
			#echo "file creat ($iter) failed at length ${#_fpath}"
			file_expected_fail=1
		fi
	fi

	settest link
	genprofile $tmpdir/**:$linkperm
	if [ -f $file ]
	then
		_f=$file 
	elif [ -f ../$file ]
	then
		_f=../$file
	else
		echo "unable to find file to link" >&2
		exit 1
	fi

	runchecktest "LONGPATH LINK ($iter)" $fstatus $_f $file2

	if [ $fstatus = "pass" ]
	then
		if [ -f $file2 ]
		then
			#echo "file link ($iter) passed at length ${#_dpath}"
			:
		else
			echo "FAIL: $file2 ($_iter) was not linked" >&2
		fi
	elif [ $fstatus = "fail" ]
	then
		if [ -f $file2 ]
		then
			echo "file link ($iter) incorrectly generated file at length ${#_dpath}"
		else
			#echo "file link ($iter) failed at length ${#_fpath}"
			link_expected_fail=1
		fi
	fi
			
	if [ $mkdir_expected_fail -eq 1 -a \
	     $file_expected_fail -eq 1 -a \
	     $link_expected_fail -eq 1 ]
	then
		break
	fi
	
	: $((iter++))
done
