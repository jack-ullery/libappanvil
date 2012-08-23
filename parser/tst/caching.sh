#!/bin/bash
# These tests will stop running as soon as a failure is seen since they tend to build
# on the actions and results of the prior tests.
set -e

# This test requires introspection
if [ ! -d /sys/kernel/security/apparmor ]; then
    echo "WARNING: /sys/kernel/security/apparmor does not exist. Skipping tests"
    echo "requiring introspection."
    exit 0
fi

# fake base directory
basedir=$(mktemp -d -t aa-cache-XXXXXX)
trap "rm -rf $basedir" EXIT
mkdir -p $basedir/cache

ARGS="--base $basedir --skip-kernel-load"

profile=sbin.pingy
cp caching.profile $basedir/$profile

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

echo -n "Profiles are not cached by default: "
../apparmor_parser $ARGS -q -r $basedir/$profile
[ -f $basedir/cache/$profile ] && echo "FAIL ($basedir/cache/$profile exists)" && exit 1
echo "ok"

echo -n "Profiles are not cached when using --skip-cache: "
../apparmor_parser $ARGS -q --write-cache --skip-cache -r $basedir/$profile
[ -f $basedir/cache/$profile ] && echo "FAIL ($basedir/cache/$profile exists)" && exit 1
echo "ok"

sleep $timeout

echo -n "Profiles are cached when requested: "
../apparmor_parser $ARGS -q --write-cache -r $basedir/$profile
[ ! -f $basedir/cache/$profile ] && echo "FAIL ($basedir/cache/$profile does not exist)" && exit 1
echo "ok"

read_features_dir()
{
    directory="$1"
    if [ ! -d "$directory" ] ; then
	return
    fi
    for f in `ls -AU "$directory"` ; do
	if [ -f "$directory/$f" ] ; then
	    read -r -d "" KF < "$directory/$f" || true
	    echo -e "$f {$KF\n}"
	elif [ -d "$directory/$f" ] ; then
	    echo -n "$f {"
	    KF=`read_features_dir "$directory/$f" "$KF"` || true
	    echo "$KF"
	    echo -e "}"
	fi
    done
}

echo -n "Kernel features are written to cache: "
[ ! -f $basedir/cache/.features ] && echo "FAIL ($basedir/cache/.features missing)" && exit 1
read -r -d "" CF < $basedir/cache/.features || true
if [ -d /sys/kernel/security/apparmor/features ] ; then
    KF=`read_features_dir /sys/kernel/security/apparmor/features`
else
    read -r -d "" KF < /sys/kernel/security/apparmor/features || true
fi
[ "$CF" != "$KF" ] && echo -e "FAIL (feature text mismatch:\n  cache '$CF'\nvs\n  kernel '$KF')" && exit 1
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

echo -n "Cache writing is skipped when features do not match and not cleared: "
rm $basedir/cache/$profile
../apparmor_parser $ARGS -v --write-cache --skip-bad-cache -r $basedir/$profile | grep -q 'Replacement succeeded for' || { echo "FAIL"; exit 1; }
[ -f $basedir/cache/$profile ] && echo "FAIL ($basedir/cache/$profile exists)" && exit 1
echo "ok"

rm -f $basedir/cache/.features || true
rm -f $basedir/cache/$profile || true
echo -n "monkey" > $basedir/cache/.features
echo -n "monkey" > $basedir/cache/$profile
echo -n "monkey" > $basedir/cache/monkey
../apparmor_parser $ARGS -v --write-cache -r $basedir/$profile | grep -q 'Replacement succeeded for' || { echo "Cache clear setup FAIL"; exit 1; }
echo -n "Cache clear updates features: "
echo -n "monkey" | diff -q $basedir/cache/.features - | grep -q 'differ' || { echo "FAIL"; exit 1; }
echo "ok"
echo -n "Cache clear writes updated profile: "
echo -n "monkey" | diff -q $basedir/cache/$profile - | grep -q 'differ' || { echo "FAIL"; exit 1; }
echo "ok"
echo -n "Cache clear cleans out all files: "
[ -f $basedir/cache/monkey ] && { echo "FAIL"; exit 1; }
echo "ok"

rm -f $basedir/cache/monkey
rm -f $basedir/cache/.features || true
rm -f $basedir/cache/$profile || true
echo -n "monkey" > $basedir/cache/.features
echo -n "monkey" > $basedir/cache/$profile
echo -n "monkey" > $basedir/cache/monkey
echo -n "Cache purge remove profiles unconditionally: "
../apparmor_parser $ARGS -v --purge-cache -r $basedir/$profile || { echo "Cache clear setup FAIL"; exit 1; }
[ -f $basedir/cache/.features ] && { echo "FAIL"; exit 1; }
[ -f $basedir/cache/$profile ] && { echo "FAIL"; exit 1; }
[ -f $basedir/cache/monkey ] && { echo "FAIL"; exit 1; }
echo "ok"

echo -n "Profiles are cached when requested (again): "
rm -f $basedir/cache/.features || true
rm -f $basedir/cache/$profile || true
../apparmor_parser $ARGS -q --write-cache -r $basedir/$profile
[ ! -f $basedir/cache/$profile ] && echo "FAIL ($basedir/cache/$profile does not exist)" && exit 1
echo "ok"

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

echo -n "Cache reading is skipped when parser is newer: "
mkdir $basedir/parser
cp ../apparmor_parser $basedir/parser/
$basedir/parser/apparmor_parser $ARGS -v -r $basedir/$profile | grep -q 'Replacement succeeded for' || { echo "FAIL"; exit 1; }
echo "ok"

echo -n "Cache reading is skipped when parser in \$PATH is newer: "
(PATH=$basedir/parser/ /bin/sh -c "apparmor_parser $ARGS -v -r $basedir/$profile") | grep -q 'Replacement succeeded for' || { echo "FAIL"; exit 1; }
echo "ok"
