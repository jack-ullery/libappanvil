#!/bin/bash
# These tests will stop running as soon as a failure is seen since they tend to build
# on the actions and results of the prior tests.
set -e

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
echo "ok"

echo -n "Profiles are not cached when using --skip-cache: "
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

# Detect and slow down cache test when filesystem can't represent nanosecond delays.
timeout=0.1
touch $basedir/test1
sleep $timeout
touch $basedir/test2
TIMES=$(stat $basedir/test1 $basedir/test2 -c %z | cut -d" " -f2 | cut -d. -f2 | sort -u | wc -l)
if [ $TIMES -ne 2 ]; then
    echo "WARNING: $basedir lacks nanosecond timestamp resolution, falling back to slower test"
    timeout=1
fi
rm -f $basedir/test1 $basedir/test2

echo -n "Cache reading is skipped when profile is newer: "
sleep $timeout
touch $basedir/$profile
../apparmor_parser $ARGS -v -r $basedir/$profile | grep -q 'Replacement succeeded for' || { echo "FAIL"; exit 1; }
echo "ok"

echo -n "Cache is used when cache is newer: "
sleep $timeout
touch $basedir/cache/$profile
../apparmor_parser $ARGS -v -r $basedir/$profile | grep -q 'Cached reload succeeded' || { echo "FAIL"; exit 1; }
echo "ok"
