#!/usr/bin/python

import os
import argparse

import apparmor.aa as apparmor

parser = argparse.ArgumentParser(description='Cleanup the profiles for the given programs')
parser.add_argument('-d', type=str, help='path to profiles')
parser.add_argument('program', type=str, nargs='+', help='name of program')
args = parser.parse_args()

profiling = args.program
profiledir = args.d

if profiledir:
    apparmor.profile_dir = apparmor.get_full_path(profiledir)
    if not os.path.isdir(apparmor.profile_dir):
        raise apparmor.AppArmorException("%s is not a directory."%profiledir)

for p in sorted(profiling):
    if not p:
        continue
    
    program = None
    if os.path.exists(p):
        program = apparmor.get_full_path(p).strip()
    else:
        which = apparmor.which(p)
        if which:
            program = apparmor.get_full_path(which)
    
    if os.path.exists(program):
        apparmor.read_profiles()
        filename = apparmor.get_profile_filename(program)
        if filename:
            apparmor.write_profile_ui_feedback(program)
            apparmor.reload_base(program)
        else:
            raise apparmor.AppArmorException(_('The profile for %s does not exists. Nothing to clean.')%p)
        
