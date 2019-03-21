#! /bin/bash
#	Copyright (C) 2018 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME xattrs_profile
#=DESCRIPTION
# This test verifies that profiles using xattr matching match correctly. 
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. $bin/prologue.inc

file="$bin/xattrs_profile"

requires_kernel_features domain/attach_conditions/xattr


# Clean up existing xattrs
clean_xattr()
{
    setfattr --remove=user.foo $file 2> /dev/null || true
    setfattr --remove=user.bar $file 2> /dev/null || true
    setfattr --remove=user.spam $file 2> /dev/null || true
}

set_xattr()
{
    setfattr --name="$1" --value="$2" $file
}

clean_xattr

# Test basic basic xattr

genprofile "image=profile_1" \
  "addimage:$file" \
  "path:$file" \
  "/proc/*/attr/current:r" \
  "xattr:user.foo:hello" \
  "xattr:user.bar:bye" \
  --nowarn

runchecktest "Path with no xattrs" pass unconfined
set_xattr "user.foo" "hello"
runchecktest "Path only matching one xattr" pass unconfined
set_xattr "user.bar" "hello"
runchecktest "Path not matching xattr value" pass unconfined
set_xattr "user.bar" "bye"
runchecktest "Path matching xattrs value" pass profile_1
set_xattr "user.spam" "hello"
runchecktest "Path matching xattrs value with additional xattr" pass profile_1

clean_xattr

# Test basic xattrs with wildcards

genprofile "image=profile_1" \
  "addimage:$file" \
  "path:$bin/xattrs_profile" \
  "/proc/*/attr/current:r" \
  "xattr:user.foo:hello/*" \
  "xattr:user.bar:*"

runchecktest "Path with no xattrs" pass unconfined
set_xattr "user.foo" "hello"
runchecktest "Path not matching xattr regexs" pass unconfined
set_xattr "user.bar" "hello"
runchecktest "Path matching one xattr regex" pass unconfined
set_xattr "user.foo" "hello/foo"
runchecktest "Path matching xattrs regex" pass profile_1
set_xattr "user.spam" "bye"
runchecktest "Path matching xattrs regex with additional xattr" pass profile_1

clean_xattr

# Test that longer paths have higher priority than xattrs

genprofile "image=profile_1" \
  "addimage:$file" \
  "path:$bin/*" \
  "/proc/*/attr/current:r" \
  "xattr:user.foo:hello" \
  -- \
  "image=profile_2" \
  "addimage:$file" \
  "path:$bin/xattrs_profile" \
  "/proc/*/attr/current:r"

runchecktest "Path with no xattrs" pass profile_2
set_xattr "user.foo" "hello"
runchecktest "Path more specific than xattr profile" pass profile_2

clean_xattr

# Test that longer paths with xattrs have higher priority than shorter paths

genprofile "image=profile_1" \
  "addimage:$file" \
  "path:$file" \
  "/proc/*/attr/current:r" \
  "xattr:user.foo:hello" \
  -- \
  "image=profile_2" \
  "addimage:$file" \
  "path:$bin/xattrs_*" \
  "/proc/*/attr/current:r"

runchecktest "Path with no xattrs" pass profile_2
set_xattr "user.foo" "hello"
runchecktest "Path with xattrs longer" pass profile_1

clean_xattr

# Test that xattrs break path length ties

genprofile "image=profile_1" \
  "addimage:$file" \
  "path:$file" \
  "/proc/*/attr/current:r" \
  "xattr:user.foo:hello" \
  -- \
  "image=profile_2" \
  "addimage:$file" \
  "path:$file" \
  "/proc/*/attr/current:r"

runchecktest "Path with no xattrs" pass profile_2
set_xattr "user.foo" "hello"
runchecktest "Profiles with xattrs and same path length" pass profile_1

clean_xattr

# xattr matching doesn't work if the xattr value has a null character. This
# impacts matching security.ima and security.evm values.
#
# A kernel patch has been proposed to fix this:
# https://lists.ubuntu.com/archives/apparmor/2018-December/011882.html

genprofile "image=profile_1" \
  "addimage:$file" \
  "path:$file" \
  "/proc/*/attr/current:r" \
  "xattr:user.foo:**" \

runchecktest "Path with no xattrs" pass unconfined
set_xattr "user.foo" "ab"
runchecktest "matches value" pass profile_1
set_xattr "user.foo" "0x610062" # "a\0b"
runchecktest "xattr values with null characters don't work" pass unconfined

clean_xattr
