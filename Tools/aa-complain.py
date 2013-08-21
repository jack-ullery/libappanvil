#!/usr/bin/python
import sys
import os
import argparse

import apparmor.aa as apparmor

parser = argparse.ArgumentParser(description='Switch the given program to complain mode')
parser.add_argument('-d', type=str, help='path to profiles')
parser.add_argument('program', type=str, nargs='+', help='name of program to switch to complain mode')
args = parser.parse_args()

profiling = args.program
profiledir = args.d

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
    
    if os.path.exists(program):
        apparmor.read_profiles()
        filename = apparmor.get_profile_filename(program)
        
        if not os.path.isfile(filename) or apparmor.is_skippable_file(filename):
            continue
        
        sys.stdout.write(_('Setting %s to complain mode.\n')%program)
        
        apparmor.set_profile_flags(filename, 'complain')
        
        cmd_info = apparmor.cmd(['cat', filename, '|', parser, '-I%s'%apparmor.profile_dir, '-R 2>&1', '1>/dev/null'])
        if cmd_info[0] != 0:
            raise apparmor.AppArmorException(cmd_info[1])
    else:
        if '/' not in p:
            apparmor.UI_Info(_("Can't find %s in the system path list. If the name of the application is correct, please run 'which %s' as a user with correct PATH environment set up in order to find the fully-qualified path.")%(p, p))
        else:
            apparmor.UI_Info(_("%s does not exist, please double-check the path.")%p)
        sys.exit(1)
            
sys.exit(0)
        
