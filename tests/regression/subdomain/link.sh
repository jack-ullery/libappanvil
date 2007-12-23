#! /bin/bash
# $Id$

#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME link
#=DESCRIPTION
# Link requires 'l' permission on the link and that permissions on the
#links rwmx perms are a subset of the targets perms, and if x is present
#that the link and target have the same x qualifiers.
# This test verifies matching, non-matching and missing link
# permissions in a profile.
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

target=$tmpdir/target
linkfile=$tmpdir/linkfile
okperm=rwixl
badperm=rwl
nolinkperm=rwix


#test for $1 in $2
function perm_is_subset () {
	# zero length substring always matches
	if [ -z $1 ] ; then
		echo $2;
		return 0;
	fi

	case "$2" in
	*$1*) echo ${2##${2/$1*/}}; return 0;;
	esac

	#handle the special cases
	#ix implies mix
	local target=${2/ix/mix}
	case "$target" in
	*$1*) echo ${target##${target/$1*/}}; return 0;;
        esac

	# treat safe PUx as subset of unsafe pux
	local linkfile=${1/Px/px}
	linkfile=${linkfile/Ux/ux}
	case "$target" in
	*$linkfile*) echo ${target##${target/$linkfile*/}}; return 0;
	esac
	
	# permute rw to do string match of rm rwm
	target=${target/rw/wr}
	case "$target" in
        *$1*) echo ${target##${target/$linkfile*/}}; return 0;;
	esac

}

PERMS="r w m ix px ux Px Ux l rw rm rix rpx rux rPx rUx rl wm wix wpx wux \
	wPx wUx wl mix mpx mux mPx mUx ml ixl pxl uxl Pxl Uxl rwm rwix rwpx \
	rwux rwPx rwUx rwl rmix rmpx rmux rmPx rmUx rml wmix wmpx wmux wmPx \
	wmUx wml mixl mpxl muxl mPxl mUxl rwmix rwmpx rwmux rwmPx rwmUx \
	rwml wmixl wmpxl wmuxl wmPxl wmUxl rwmixl rwmpxl rwmuxl rwmPxl \
	rwmUxl"


# unconfined test - no target file
runchecktest "unconfined - no target" fail $target $linkfile

touch $target
# unconfined test
runchecktest "unconfined" pass $target $linkfile

rm -rf $target
# Link no perms on link or target - no target file
genprofile
runchecktest "link no target (no perms) -> target (no perms)" fail $target $linkfile
rm -rf $linkfile

touch $target
# Link no perms on link or target 
runchecktest "link (no perms) -> target (no perms)" fail $target $linkfile
rm -rf $linkfile

# link no perms
for TARGET_PERM in ${PERMS} ; do
	genprofile $target:$TARGET_PERM
	runchecktest "link (no perms) -> target ($TARGET_PERM)" fail $target $linkfile
	rm -rf $linkfile
done

# target no perms
for LINK_PERM in ${PERMS} ; do
	genprofile $linkfile:$LINK_PERM
	runchecktest "link ($LINK_PERM) -> target (no perms)" fail $target $linkfile
	rm -rf $linkfile
done

# all other combination of perms
for LINK_PERM in ${PERMS} ; do
	for TARGET_PERM in ${PERMS} ; do
		l_in_perms=${LINK_PERM/*l/l}
		perms_no_link=${LINK_PERM/l/}
		link_subset=`perm_is_subset ${perms_no_link} ${TARGET_PERM}`
		if [ "$l_in_perms" == "l" -a -n "$perms_no_link" -a -n "$link_subset" ]
		then
			expected_result=pass
		else
			expected_result=fail
		fi
#echo "testing $LINK_PERM -> $TARGET_PERM = $l_in_perms, $perms_no_link, $link_subset $expected_result"
		genprofile $linkfile:$LINK_PERM $target:$TARGET_PERM
		runchecktest "link ($LINK_PERM) -> target ($TARGET_PERM)" ${expected_result} $target $linkfile
		rm -rf $linkfile

	done
done

