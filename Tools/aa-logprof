#!/usr/bin/python

import argparse
import os

import apparmor.aa as apparmor

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
    raise apparmor.AppArmorException(_('It seems AppArmor was not started. Please enable AppArmor and try again.'))

if profiledir:
    apparmor.profiledir = apparmor.get_full_path(profiledir)
    if not os.path.isdir(apparmor.profiledir):
        raise apparmor.AppArmorException("%s is not a directory."%profiledir)

apparmor.loadincludes()

apparmor.do_logprof_pass(logmark)

