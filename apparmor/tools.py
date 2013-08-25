import os
import re
import sys

import apparmor.aa as apparmor
    
class aa_tools:
    def __init__(self, tool_name, args):
        self.name = tool_name
        self.profiledir = args.d
        self.profiling = args.program
        
        if tool_name in ['audit', 'complain', 'enforce']:
            self.remove = args.remove
        elif tool_name == 'disable':
            self.revert = args.revert
            self.disabledir = apparmor.profile_dir+'/disable'
        elif tool_name == 'autodep':
            self.force = args.force
            self.aa_mountpoint = apparmor.check_for_apparmor()
    
    def check_profile_dir(self):
        if self.profiledir:
            apparmor.profile_dir = apparmor.get_full_path(self.profiledir)
            if not os.path.isdir(apparmor.profile_dir):
                raise apparmor.AppArmorException("%s is not a directory." %self.profiledir)
    
    def check_disable_dir(self):
        if not os.path.isdir(self.disabledir):
            raise apparmor.AppArmorException("Can't find AppArmor disable directory %s." %self.disabledir)
    
    def act(self):
        for p in self.profiling:
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
                if self.name == 'autodep':
                    self.use_autodep(program)
                
                else:
                    apparmor.read_profiles()
                    filename = apparmor.get_profile_filename(program)
                    
                    if not os.path.isfile(filename) or apparmor.is_skippable_file(filename):
                        continue
                    
                    if self.name == 'enforce':
                        apparmor.UI_Info(_('Setting %s to enforce mode.\n')%program)
                        apparmor.change_profile_flags(filename, '', self.remove)
                        #apparmor.set_profile_flags(filename, '')
                        self.remove_symlinks(filename)
                        
                    elif self.name == 'disable':
                        apparmor.UI_Info(_('Disabling %s.\n')%program)
                        if not self.revert:
                            self.disable_profile(filename)
                        else:
                            self.remove_disable_link(filename)
                    else:
                        apparmor.UI_Info(_('Setting %s to %s mode.\n')%(program, self.name))
                        apparmor.change_profile_flags(filename, self.name, self.remove)
                        #apparmor.set_profile_flags(filename, self.name)
                    
                    cmd_info = apparmor.cmd(['cat', filename, '|', apparmor.parser, '-I%s'%apparmor.profile_dir, '-R 2>&1', '1>/dev/null'])
                    
                    if cmd_info[0] != 0:
                        raise apparmor.AppArmorException(cmd_info[1])
            
            else:
                if '/' not in p:
                    apparmor.UI_Info(_("Can't find %s in the system path list. If the name of the application is correct, please run 'which %s' as a user with correct PATH environment set up in order to find the fully-qualified path.")%(p, p))
                else:
                    apparmor.UI_Info(_("%s does not exist, please double-check the path.")%p)
                    sys.exit(1)
        
    def use_autodep(self, program):
        apparmor.check_qualifiers(program)           
        
        if os.path.exists(apparmor.get_profile_filename(program) and not self.force):
            apparmor.UI_Info('Profile for %s already exists - skipping.'%program)
        else:
            apparmor.autodep(program)
            if self.aa_mountpoint:
                apparmor.reload(program)
                    
    def remove_symlinks(self, filename):
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
    
    def remove_disable_link(self, filename): 
        # Remove the file from disable dir
        bname = os.path.basename(filename)
        if not bname:
            raise apparmor.AppArmorException(_('Unable to find basename for %s.')%filename)
                          
        link = '%s/%s'%(self.disabledir, bname)
        if os.path.exists(link):
            os.remove(link)
        
    def disable_profile(self, filename):
        bname = os.path.basename(filename)
        if not bname:
            raise apparmor.AppArmorException(_('Unable to find basename for %s.')%filename)
                          
        link = '%s/%s'%(self.disabledir, bname)
        if not os.path.exists(link):
            try:
                os.symlink(filename, link)
            except:
                raise apparmor.AppArmorException('Could not create %s symlink to %s.'%(link, filename))