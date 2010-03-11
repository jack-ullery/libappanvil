#!/bin/sh

. ./uservars.inc

${subdomain_parser} change_hat.profile child.profile open.profile 

./open & ./open /tmp/foobar &

./child & ./child &

./change_hat > /dev/null 2>&1 & ./change_hat /tmp/foo > /dev/null 2>&1 &

while :
do
	cat change_hat.profile | ${subdomain_parser} -r > /dev/null 2>&1 &
	cat child.profile | ${subdomain_parser} -r > /dev/null 2>&1 &
	cat open.profile | ${subdomain_parser} -r > /dev/null 2>&1 &
done &

