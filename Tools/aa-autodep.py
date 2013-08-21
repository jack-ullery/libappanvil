#!/usr/bin/python
import sys
import os
import argparse

import apparmor.aa as apparmor

parser = argparse.ArgumentParser(description='Disable the profile for the given programs')
parser.add_argument('--force', type=str, help='path to profiles')
parser.add_argument('-d', type=str, help='path to profiles')
parser.add_argument('program', type=str, nargs='+', help='name of program to have profile disabled')
args = parser.parse_args()

force = args.force
profiledir = args.d
profiling = args.program

aa_mountpoint = apparmor.check_for_apparmor()

if profiledir:
    apparmor.profile_dir = apparmor.get_full_path(profiledir)
    if not os.path.isdir(apparmor.profile_dir):
        raise apparmor.AppArmorException("Can't find AppArmor profiles in %s." %profiledir)

for p in profiling:
    if not p:
        continue
    
    program = None
    if os.path.exists(p):
        program = apparmor.get_full_path(p).strip()
    else:
        which = apparmor.which(p)
        if which:
            program = apparmor.get_full_path(which)
    
    apparmor.check_qualifiers(program)
    
    if os.path.exists(program):
        if os.path.exists(apparmor.get_profile_filename(program) and not force):
            apparmor.UI_Info('Profile for %s already exists - skipping.'%program)
        else:
            apparmor.autodep(program)
            if aa_mountpoint:
                apparmor.reload(program)
    else:
        if '/' not in p:
            apparmor.UI_Info(_("Can't find %s in the system path list. If the name of the application is correct, please run 'which %s' as a user with correct PATH environment set up in order to find the fully-qualified path.")%(p, p))
        else:
            apparmor.UI_Info(_("%s does not exist, please double-check the path.")%p)
        sys.exit(1)
            
sys.exit(0)
