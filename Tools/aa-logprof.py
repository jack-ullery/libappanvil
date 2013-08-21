#!/usr/bin/python
import sys
import apparmor.aa as apparmor
import os
import argparse

parser = argparse.ArgumentParser(description='Process log entries to generate profiles')
parser.add_argument('-d', type=str, help='path to profiles')
parser.add_argument('-f', type=str, help='path to logfile')
parser.add_argument('-m', type=str, help='mark in the log to start processing after')
args = parser.parse_args()

profiledir = args.d
filename = args.f
logmark = args.m or ''

aa_mountpoint = apparmor.check_for_apparmor()
if not aa_mountpoint:
    raise apparmor.AppArmorException(_('AppArmor seems to have not been started. Please enable AppArmor and try again.'))

if profiledir:
    apparmor.profiledir = apparmor.get_full_path(profiledir)
    if not os.path.isdir(apparmor.profiledir):
        raise apparmor.AppArmorException("Can't find AppArmor profiles in %s." %profiledir)

apparmor.loadincludes()

apparmor.do_logprof_pass(logmark)

sys.exit(0)
