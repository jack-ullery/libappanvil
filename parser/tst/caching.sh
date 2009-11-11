#!/bin/bash
set -e

[ -w /etc/passwd ] || { echo "Must be root to run this test" >&2; exit 1; }

# fake base directory
basedir=$(mktemp -d -t aa-cache-XXXXXX)
trap "rm -rf $basedir" EXIT
mkdir -p $basedir/cache

ARGS="--base $basedir --skip-kernel-load"

profile=sbin.pingy
cp caching.profile $basedir/$profile

echo -n "Profiles are not cached by default: "
../apparmor_parser $ARGS -q -r $basedir/$profile
[ -f $basedir/cache/$profile ] && echo "FAIL ($basedir/cache/$profile exists)" && exit 1
../apparmor_parser $ARGS -q --write-cache --skip-cache -r $basedir/$profile
[ -f $basedir/cache/$profile ] && echo "FAIL ($basedir/cache/$profile exists)" && exit 1
echo "ok"

echo -n "Profiles are cached when requested: "
../apparmor_parser $ARGS -q --write-cache -r $basedir/$profile
[ ! -f $basedir/cache/$profile ] && echo "FAIL ($basedir/cache/$profile does not exist)" && exit 1
echo "ok"

echo -n "Kernel features are written to cache: "
[ ! -f $basedir/cache/.features ] && echo "FAIL ($basedir/cache/.features missing)" && exit 1
read CF < $basedir/cache/.features || true
read KF < /sys/kernel/security/apparmor/features || true
[ "$CF" != "$KF" ] && echo "FAIL (feature text mismatch: cache '$CF' vs kernel '$KF')" && exit 1
echo "ok"

echo -n "Cache is loaded when it exists and features match: "
../apparmor_parser $ARGS -v -r $basedir/$profile | grep -q 'Cached reload succeeded' || { echo "FAIL"; exit 1; }
echo "ok"

echo -n "Cache is not loaded when skipping is requested: "
../apparmor_parser $ARGS -v --skip-read-cache -r $basedir/$profile | grep -q 'Replacement succeeded for' || { echo "FAIL"; exit 1; }
../apparmor_parser $ARGS -v --skip-cache -r $basedir/$profile | grep -q 'Replacement succeeded for' || { echo "FAIL"; exit 1; }
echo "ok"

echo -n "Cache reading is skipped when features do not match cache: "
echo -n "monkey" > $basedir/cache/.features
../apparmor_parser $ARGS -v -r $basedir/$profile | grep -q 'Replacement succeeded for' || { echo "FAIL"; exit 1; }
echo "ok"

echo -n "Cache writing is skipped when features do not match cache: "
rm $basedir/cache/$profile
../apparmor_parser $ARGS -v --write-cache -r $basedir/$profile | grep -q 'Replacement succeeded for' || { echo "FAIL"; exit 1; }
[ -f $basedir/cache/$profile ] && echo "FAIL ($basedir/cache/$profile exists)" && exit 1
echo "ok"

echo -n "Profiles are cached when requested (again): "
rm -f $basedir/cache/.features || true
rm -f $basedir/cache/$profile || true
../apparmor_parser $ARGS -q --write-cache -r $basedir/$profile
[ ! -f $basedir/cache/$profile ] && echo "FAIL ($basedir/cache/$profile does not exist)" && exit 1
echo "ok"

echo -n "Cache reading is skipped when profile is newer: "
sleep 0.1
touch $basedir/$profile
../apparmor_parser $ARGS -v -r $basedir/$profile | grep -q 'Replacement succeeded for' || { echo "FAIL (does your /tmp support nanosecond file stamp resolution?)"; exit 1; }
echo "ok"

echo -n "Cache is used when cache is newer: "
sleep 0.1
touch $basedir/cache/$profile
../apparmor_parser $ARGS -v -r $basedir/$profile | grep -q 'Cached reload succeeded' || { echo "FAIL (does your /tmp support nanosecond file stamp resolution?)"; exit 1; }
echo "ok"
