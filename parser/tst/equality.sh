#!/bin/bash
#
#   Copyright (c) 2013
#   Canonical, Ltd. (All rights reserved)
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of version 2 of the GNU General Public
#   License published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, contact Canonical Ltd.
#

# Tests for post-parser equality among multiple profiles. These tests are
# useful to verify that keyword aliases, formatting differences, etc., all
# result in the same parser output.

set -o pipefail

APPARMOR_PARSER="${APPARMOR_PARSER:-../apparmor_parser}"
fails=0
errors=0

hash_binary_policy()
{
	printf %s "$1" | ${APPARMOR_PARSER} -qS 2>/dev/null| md5sum | cut -d ' ' -f 1
	return $?
}

# verify_binary_equality - compares the binary policy of multiple profiles
# $1: A short description of the test
# $2: The known-good profile
# $3..$n: The profiles to compare against $2
#
# Upon failure/error, prints out the test description and profiles that failed
# and increments $fails or $errors for each failure and error, respectively
verify_binary_equality()
{
	local desc=$1
	local good_profile=$2
	local good_hash
	local ret=0

	shift
	shift

	printf "Binary equality %s ..." "$desc"
	good_hash=$(hash_binary_policy "$good_profile")
	if [ $? -ne 0 ]
	then
		printf "\nERROR: Error hashing the following \"known-good\" profile:\n%s\n\n" \
		       "$good_profile" 1>&2
		((errors++))
		return $((ret + 1))
	fi

	for profile in "$@"
	do
		hash=$(hash_binary_policy "$profile")
		if [ $? -ne 0 ]
		then
			printf "\nERROR: Error hashing the following profile:\n%s\n\n" \
			       "$profile" 1>&2
			((errors++))
			((ret++))
		elif [ "$hash" != "$good_hash" ]
		then
			printf "\nFAIL: Hash values do not match\n" 2>&1
			printf "known-good (%s) != profile-under-test (%s) for the following profile:\n%s\n\n" \
				"$good_hash" "$hash" "$profile" 1>&2
			((fails++))
			((ret++))
		fi
	done

	if [ $ret -eq 0 ]
	then
		printf " ok\n\n"
	fi

	return $ret
}

verify_binary_equality "dbus send" \
	"/t { dbus send, }" \
	"/t { dbus write, }" \
	"/t { dbus w, }"

verify_binary_equality "dbus receive" \
	"/t { dbus receive, }" \
	"/t { dbus read, }" \
	"/t { dbus r, }"

verify_binary_equality "dbus send + receive" \
	"/t { dbus (send, receive), }" \
	"/t { dbus (read, write), }" \
	"/t { dbus (r, w), }" \
	"/t { dbus (rw), }" \
	"/t { dbus rw, }" \

verify_binary_equality "dbus all accesses" \
	"/t { dbus (send, receive, bind), }" \
	"/t { dbus (read, write, bind), }" \
	"/t { dbus (r, w, bind), }" \
	"/t { dbus (rw, bind), }" \
	"/t { dbus (), }" \
	"/t { dbus, }" \

verify_binary_equality "dbus implied accesses for services" \
	"/t { dbus bind name=com.foo, }" \
	"/t { dbus name=com.foo, }"

verify_binary_equality "dbus implied accesses for messages" \
	"/t { dbus (send, receive) path=/com/foo interface=org.foo, }" \
	"/t { dbus path=/com/foo interface=org.foo, }"

verify_binary_equality "dbus implied accesses for messages with peer names" \
	"/t { dbus (send, receive) path=/com/foo interface=org.foo peer=(name=com.foo), }" \
	"/t { dbus path=/com/foo interface=org.foo peer=(name=com.foo), }" \
	"/t { dbus (send, receive) path=/com/foo interface=org.foo peer=(name=(com.foo)), }" \
	"/t { dbus path=/com/foo interface=org.foo peer=(name=(com.foo)), }"

verify_binary_equality "dbus implied accesses for messages with peer labels" \
	"/t { dbus (send, receive) path=/com/foo interface=org.foo peer=(label=/usr/bin/app), }" \
	"/t { dbus path=/com/foo interface=org.foo peer=(label=/usr/bin/app), }"

verify_binary_equality "dbus element parsing" \
	"/t { dbus bus=b path=/ interface=i member=m peer=(name=n label=l), }" \
	"/t { dbus bus=\"b\" path=\"/\" interface=\"i\" member=\"m\" peer=(name=\"n\" label=\"l\"), }" \
	"/t { dbus bus=(b) path=(/) interface=(i) member=(m) peer=(name=(n) label=(l)), }" \
	"/t { dbus bus=(\"b\") path=(\"/\") interface=(\"i\") member=(\"m\") peer=(name=(\"n\") label=(\"l\")), }" \
	"/t { dbus bus =b path =/ interface =i member =m peer =(name =n label =l), }" \
	"/t { dbus bus= b path= / interface= i member= m peer= (name= n label= l), }" \
	"/t { dbus bus = b path = / interface = i member = m peer = ( name = n label = l ), }"

verify_binary_equality "dbus access parsing" \
	"/t { dbus, }" \
	"/t { dbus (), }" \
	"/t { dbus (send, receive, bind), }" \
	"/t { dbus (send receive bind), }" \
	"/t { dbus (send,	receive                  bind), }" \
	"/t { dbus (send,receive,bind), }" \
	"/t { dbus (send,receive,,,,,,,,,,,,,,,,bind), }" \
	"/t { dbus (send,send,send,send send receive,bind), }" \

if [ $fails -ne 0 -o $errors -ne 0 ]
then
	printf "ERRORS: %d\nFAILS: %d\n" $errors $fails 2>&1
	exit $(($fails + $errors))
fi

printf "PASS\n"
exit 0
