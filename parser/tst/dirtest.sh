#!/bin/sh
#
#   Copyright (c) 2022
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

# simple test to ensure dir is being iterated as expected
# yes this needs to be improved and reworked


# passed in by Makefile
#APPARMOR_PARSER="${APPARMOR_PARSER:-../apparmor_parser}"


do_tst() {
	local msg="$1"
	local expected="$2"
	local rc=0
	shift 2
	#global tmpdir

	${APPARMOR_PARSER} "$@" > "$tmpdir/out.unsorted" 2>/dev/null
	rc=$?
	LC_ALL=C sort "$tmpdir/out.unsorted" > "$tmpdir/out"
	if [ $rc -ne 0 ] && [ "$expected" != "fail" ] ; then
		echo "failed: expected \"$expected\" but parser returned error"
		return 1
	fi
	if [ $rc -eq 0 ] && [ "$expected" = "fail" ] ; then
		echo "succeeded unexpectedly: expected \"$expected\" but parser returned success"
		return 1
	fi
	if ! diff -q "$tmpdir/out" dirtest/dirtest.out ; then
		echo "failed: expected \"$expected\" but output comparison failed"
		diff -u dirtest/dirtest.out "$tmpdir/out"
		return 1
	fi

	return 0
}

tmpdir=$(mktemp -d "$tmpdir.XXXXXXXX")
chmod 755 "$tmpdir"
export tmpdir

rc=0

# pass - no parser errors and output matches
# error - parser error and output matches
# fail - comparison out parser output failed
do_tst "good dir list" pass -N dirtest/gooddir/ || rc=1
do_tst "bad link in dir" fail -N dirtest/badlink/ || rc=1
do_tst "bad profile in dir" fail -N dirtest/badprofile/ || rc=1

rm -rf "$tmpdir"

if [ $rc -eq 0 ] ; then
	echo "PASS"
fi

exit $rc
