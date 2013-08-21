#!/usr/bin/python
import sys
import os
import argparse

import apparmor.aa as apparmor

parser = argparse.ArgumentParser(description='Switch the given program to enforce mode')
parser.add_argument('-d', type=str, help='path to profiles')
parser.add_argument('program', type=str, nargs='+', help='name of program to switch to enforce mode')
args = parser.parse_args()

profiledir = args.d
profiling = args.program

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
        
        sys.stdout.write(_('Setting %s to enforce mode.\n')%program)
        
        apparmor.set_profile_flags(filename, '')
        
        # Remove symlink from profile_dir/force-complain
        complainlink = filename
        complainlink = re.sub('^%s'%apparmor.profile_dir, '%s/force-complain'%apparmor.profile_dir, complainlink)
        if os.path.exists(complainlink):
            os.remove(complainlink)
        
        # remove symlink in profile_dir/disable
        disablelink = filename
        disablelink = re.sub('^%s'%apparmor.profile_dir, '%s/disable'%apparmor.profile_dir, disablelink)
        if os.path.exists(disablelink):
            os.remove(disablelink)
        
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
        
