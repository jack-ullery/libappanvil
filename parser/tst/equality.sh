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

	printf "Binary equality %s" "$desc"
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
		printf " ok\n"
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
	"/t { dbus (send, receive, bind, eavesdrop), }" \
	"/t { dbus (read, write, bind, eavesdrop), }" \
	"/t { dbus (r, w, bind, eavesdrop), }" \
	"/t { dbus (rw, bind, eavesdrop), }" \
	"/t { dbus (), }" \
	"/t { dbus, }" \

verify_binary_equality "dbus implied accesses with a bus conditional" \
	"/t { dbus (send, receive, bind, eavesdrop) bus=session, }" \
	"/t { dbus (read, write, bind, eavesdrop) bus=session, }" \
	"/t { dbus (r, w, bind, eavesdrop) bus=session, }" \
	"/t { dbus (rw, bind, eavesdrop) bus=session, }" \
	"/t { dbus () bus=session, }" \
	"/t { dbus bus=session, }" \

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
	"/t { dbus (send, receive, bind, eavesdrop), }" \
	"/t { dbus (send receive bind eavesdrop), }" \
	"/t { dbus (send,	receive                  bind,  eavesdrop), }" \
	"/t { dbus (send,receive,bind,eavesdrop), }" \
	"/t { dbus (send,receive,,,,,,,,,,,,,,,,bind,eavesdrop), }" \
	"/t { dbus (send,send,send,send send receive,bind	eavesdrop), }" \

verify_binary_equality "dbus variable expansion" \
	"/t { dbus (send, receive) path=/com/foo member=spork interface=org.foo peer=(name=com.foo label=/com/foo), }" \
	"@{FOO}=foo
	    /t { dbus (send, receive) path=/com/@{FOO} member=spork interface=org.@{FOO} peer=(name=com.@{FOO} label=/com/@{FOO}), }" \
	"@{FOO}=foo
	 @{SPORK}=spork
	    /t { dbus (send, receive) path=/com/@{FOO} member=@{SPORK} interface=org.@{FOO} peer=(name=com.@{FOO} label=/com/@{FOO}), }" \
	"@{FOO}=/com/foo
            /t { dbus (send, receive) path=@{FOO} member=spork interface=org.foo peer=(name=com.foo label=@{FOO}), }" \
	"@{FOO}=com
            /t { dbus (send, receive) path=/@{FOO}/foo member=spork interface=org.foo peer=(name=@{FOO}.foo label=/@{FOO}/foo), }"

verify_binary_equality "dbus variable expansion, multiple values/rules" \
	"/t { dbus (send, receive) path=/com/foo, dbus (send, receive) path=/com/bar, }" \
	"/t { dbus (send, receive) path=/com/{foo,bar}, }" \
	"/t { dbus (send, receive) path={/com/foo,/com/bar}, }" \
	"@{FOO}=foo
	    /t { dbus (send, receive) path=/com/@{FOO}, dbus (send, receive) path=/com/bar, }" \
	"@{FOO}=foo bar
	    /t { dbus (send, receive) path=/com/@{FOO}, }" \
	"@{FOO}=bar foo
	    /t { dbus (send, receive) path=/com/@{FOO}, }" \
	"@{FOO}={bar,foo}
	    /t { dbus (send, receive) path=/com/@{FOO}, }" \
	"@{FOO}=foo
	 @{BAR}=bar
	    /t { dbus (send, receive) path=/com/{@{FOO},@{BAR}}, }" \

verify_binary_equality "dbus variable expansion, ensure rule de-duping occurs" \
	"/t { dbus (send, receive) path=/com/foo, dbus (send, receive) path=/com/bar, }" \
	"/t { dbus (send, receive) path=/com/foo, dbus (send, receive) path=/com/bar, dbus (send, receive) path=/com/bar, }" \
	"@{FOO}=bar foo bar foo
	    /t { dbus (send, receive) path=/com/@{FOO}, }" \
	"@{FOO}=bar foo bar foo
	    /t { dbus (send, receive) path=/com/@{FOO}, dbus (send, receive) path=/com/@{FOO}, }"

verify_binary_equality "dbus minimization with all perms" \
	"/t { dbus, }" \
	"/t { dbus bus=session, dbus, }" \
	"/t { dbus (send, receive, bind, eavesdrop), dbus, }"

verify_binary_equality "dbus minimization with bind" \
	"/t { dbus bind, }" \
	"/t { dbus bind bus=session, dbus bind, }" \
	"/t { dbus bind bus=system name=com.foo, dbus bind, }"

verify_binary_equality "dbus minimization with send and a bus conditional" \
	"/t { dbus send bus=system, }" \
	"/t { dbus send bus=system path=/com/foo interface=com.foo member=bar, dbus send bus=system, }" \
	"/t { dbus send bus=system peer=(label=/usr/bin/foo), dbus send bus=system, }"

verify_binary_equality "dbus minimization with an audit modifier" \
	"/t { audit dbus eavesdrop, }" \
	"/t { audit dbus eavesdrop bus=session, audit dbus eavesdrop, }"

verify_binary_equality "dbus minimization with a deny modifier" \
	"/t { deny dbus send bus=system peer=(name=com.foo), }" \
	"/t { deny dbus send bus=system peer=(name=com.foo label=/usr/bin/foo), deny dbus send bus=system peer=(name=com.foo), }" \

verify_binary_equality "dbus minimization found in dbus abstractions" \
	"/t { dbus send bus=session, }" \
	"/t { dbus send
                   bus=session
                   path=/org/freedesktop/DBus
                   interface=org.freedesktop.DBus
                   member={Hello,AddMatch,RemoveMatch,GetNameOwner,NameHasOwner,StartServiceByName}
                   peer=(name=org.freedesktop.DBus),
	      dbus send bus=session, }"

if [ $fails -ne 0 -o $errors -ne 0 ]
then
	printf "ERRORS: %d\nFAILS: %d\n" $errors $fails 2>&1
	exit $(($fails + $errors))
fi

printf "PASS\n"
exit 0
