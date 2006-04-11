#!/bin/sh

. ./uservars.inc

if [ `whoami` != root ]
then
	echo "$0: must be root" >&2
	exit 1
fi

cat change_hat.profile | $subdomain_parser -R 2>&1 > /dev/null
cat change_hat.profile | $subdomain_parser

./change_hat > /dev/null 2>&1 &

while :
do
	cat change_hat.profile | $subdomain_parser -r > /dev/null 2>&1 &
done &

