#! /bin/bash
#Copyright (C) 2022 Canonical, Ltd.
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License as
#published by the Free Software Foundation, version 2 of the
#License.

#=NAME userns
#=DESCRIPTION
# This test verifies if mediation of user namespaces is working
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

requires_kernel_features namespaces/mask/userns_create
requires_parser_support "userns,"

apparmor_restrict_unprivileged_userns_path=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
if [ ! -e $apparmor_restrict_unprivileged_userns_path ]; then
	echo "$apparmor_restrict_unprivileged_userns_path not available. Skipping tests ..."
	exit 0
fi

apparmor_restrict_unprivileged_userns=$(cat $apparmor_restrict_unprivileged_userns_path)

unprivileged_userns_clone_path=/proc/sys/kernel/unprivileged_userns_clone
if [ -e $unprivileged_userns_clone_path ]; then
	unprivileged_userns_clone=$(cat $unprivileged_userns_clone_path)
fi

restore_userns()
{
	echo $apparmor_restrict_unprivileged_userns > $apparmor_restrict_unprivileged_userns_path
}
do_onexit="restore_userns"

do_test()
{
	local desc="USERNS ($1)"
	expect_root=$2
	expect_user=$3
	generate_profile=$4

	settest userns
	$generate_profile # settest removes the profile, so load it here
	runchecktest "$desc - root" $expect_root

	settest -u "foo" userns # run tests as user foo
	$generate_profile # settest removes the profile, so load it here
	runchecktest "$desc - user" $expect_user
}

if [ $unprivileged_userns_clone -eq 0 ]; then
	echo "WARN: unprivileged_userns_clone is enabled. Both confined and unconfined unprivileged user namespaces are not allowed"

	detail="unprivileged_userns_clone disabled"
	do_test "unconfined - $detail" pass fail

	generate_profile="genprofile userns cap:sys_admin"
	do_test "confined all perms $detail" pass fail "$generate_profile"

	generate_profile="genprofile cap:sys_admin"
	do_test "confined no perms $detail" fail fail "$generate_profile"

	generate_profile="genprofile userns:create cap:sys_admin"
	do_test "confined specific perms $detail" pass fail "$generate_profile"

	exit 0
fi


# confined tests should have the same results if apparmor_restrict_unprivileged_userns is enabled or not
run_confined_tests()
{
	generate_profile="genprofile userns"
	do_test "confined all perms $1" pass pass "$generate_profile"

	generate_profile="genprofile"
	do_test "confined no perms $1" fail fail "$generate_profile"

	generate_profile="genprofile userns:create"
	do_test "confined specific perms $1" pass pass "$generate_profile"
}

# ----------------------------------------------------
# disable restrictions on unprivileged user namespaces
echo 0 > $apparmor_restrict_unprivileged_userns_path

detail="apparmor_restrict_unprivileged_userns disabled"
do_test "unconfined - $detail" pass pass

run_confined_tests "$detail"

# ----------------------------------------------------
# enable restrictions on unprivileged user namespaces
echo 1 > $apparmor_restrict_unprivileged_userns_path

detail="apparmor_restrict_unprivileged_userns enabled"
# user cannot create user namespace unless cap_sys_admin
do_test "unconfined $detail" pass fail

# it should work when running as user with cap_sys_admin
setcap cap_sys_admin+pie $bin/userns
do_test "unconfined cap_sys_admin $detail" pass pass
# remove cap_sys_admin from binary
setcap cap_sys_admin= $bin/userns

run_confined_tests "$detail"
