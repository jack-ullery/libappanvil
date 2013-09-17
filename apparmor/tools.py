import os
import re
import sys

import apparmor.aa as apparmor
    
class aa_tools:
    def __init__(self, tool_name, args):
        self.name = tool_name
        self.profiledir = args.d
        self.profiling = args.program
        self.check_profile_dir()
        
        if tool_name in ['audit', 'complain']:
            self.remove = args.remove
        elif tool_name == 'disable':
            self.revert = args.revert
            self.disabledir = apparmor.profile_dir+'/disable'
            self.check_disable_dir()
        elif tool_name == 'autodep':
            self.force = args.force
            self.aa_mountpoint = apparmor.check_for_apparmor()
        elif tool_name == 'cleanprof':
            pass
    
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
            
            if (not program or not os.path.exists(program)):
                if not program.startswith('/'):
                    program = apparmor.UI_GetString(_('The given program cannot be found, please try with the fully qualified path name of the program: '), '')
                else:
                    apparmor.UI_Info(_("%s does not exist, please double-check the path.")%program)
                    sys.exit(1)
                
            #apparmor.loadincludes()
            apparmor.read_profiles()

            if program and apparmor.profile_exists(program):#os.path.exists(program):
                if self.name == 'autodep':
                    self.use_autodep(program)
                
                elif self.name == 'cleanprof':
                    self.clean_profile(program, p)
                    
                else:
                    filename = apparmor.get_profile_filename(program)
                    
                    if not os.path.isfile(filename) or apparmor.is_skippable_file(filename):
                        apparmor.UI_Info(_('Profile for %s not found, skipping')%p)
                        
                    elif self.name == 'disable':
                        if not self.revert:
                            apparmor.UI_Info(_('Disabling %s.\n')%program)
                            self.disable_profile(filename)
                        else:
                            apparmor.UI_Info(_('Enabling %s.\n')%program)
                            self.enable_profile(filename)
                            
                    elif self.name == 'audit':
                        if not self.remove:
                            apparmor.UI_Info(_('Setting %s to audit mode.\n')%program)
                        else:
                            apparmor.UI_Info(_('Removing audit mode from %s.\n')%program)
                        apparmor.change_profile_flags(filename, 'audit', not self.remove)
                    
                    elif self.name == 'complain':
                        if not self.remove:
                            apparmor.set_complain(filename, program)
                        else:
                            apparmor.set_enforce(filename, program)
                        #apparmor.set_profile_flags(filename, self.name)
                    else:
                        # One simply does not walk in here!
                        raise apparmor.AppArmorException('Unknown tool: %s'%self.name)
                    
                    cmd_info = apparmor.cmd([apparmor.parser, filename, '-I%s'%apparmor.profile_dir, '-R 2>&1', '1>/dev/null'])
                    #cmd_info = apparmor.cmd(['cat', filename, '|', apparmor.parser, '-I%s'%apparmor.profile_dir, '-R 2>&1', '1>/dev/null'])
                    
                    if cmd_info[0] != 0:
                        raise apparmor.AppArmorException(cmd_info[1])
            
            else:
                if '/' not in p:
                    apparmor.UI_Info(_("Can't find %s in the system path list. If the name of the application is correct, please run 'which %s' as a user with correct PATH environment set up in order to find the fully-qualified path.\nPlease use the full path as parameter")%(p, p))
                else:
                    apparmor.UI_Info(_("%s does not exist, please double-check the path.")%p)
                    sys.exit(1)
    
    def clean_profile(self, program, p):
        filename = apparmor.get_profile_filename(program)
        self.delete_superfluous_rules(program, filename)
        if filename:
            apparmor.write_profile_ui_feedback(program)
            apparmor.reload_base(program)
        else:
            raise apparmor.AppArmorException(_('The profile for %s does not exists. Nothing to clean.')%p)
    
    def delete_superfluous_rules(self, program, filename):
        #Process the profile of the program
        #Process every hat in the profile individually
        file_includes = list(apparmor.filelist[filename]['include'].keys())
        print(file_includes)
        for hat in apparmor.aa[program].keys():
            #The combined list of includes from profile and the file
            includes = list(apparmor.aa[program][hat]['include'].keys()) + file_includes

            allow_net_rules =  list(apparmor.aa[program][hat]['allow']['netdomain']['rule'].keys())
            #allow_rules = [] + list(apparmor.aa[program][hat]['allow']['path'].keys())
            #allow_rules +=  list(apparmor.aa[program][hat]['allow']['netdomain']['rule'].keys()) + list(apparmor.aa[program][hat]['allow']['capability'].keys()) 
            #b=set(allow_rules)
            #print(allow_rules)
            dele = 0
            #print(includes)
     
            #Clean up superfluous rules from includes           
            for inc in includes:
                #old=dele
                if not apparmor.include.get(inc, {}).get(inc,False):
                    apparmor.load_include(inc)
                dele+= apparmor.delete_duplicates(apparmor.aa[program][hat], inc)
                #dele+= apparmor.delete_path_duplicates(apparmor.aa[program][program], str(inc), 'allow')
                #if dele>old:
                #    print(inc)     
            #allow_rules = [] + list(apparmor.aa[program][hat]['allow']['path'].keys())
            #allow_rules +=  list(apparmor.aa[program][hat]['allow']['netdomain']['rule'].keys()) + list(apparmor.aa[program][hat]['allow']['capability'].keys()) 
            #c=set(allow_rules)
            #print(b.difference(c))

            dele += self.delete_path_duplicates(apparmor.aa[program][hat], apparmor.aa[program][hat], 'allow', True)
            dele += self.delete_path_duplicates(apparmor.aa[program][hat], apparmor.aa[program][hat], 'deny', True)
            
            print(dele)
            sys.exit(0)

    def delete_path_duplicates(self, profile, profile_other, allow, same_profile=True):
        deleted = []
        #Check if any individual rule makes any rule superfluous
        for rule in profile[allow]['path'].keys():
            for entry in profile_other[allow]['path'].keys():
                if rule == entry:
                    if not same_profile:
                        deleted.append(entry)
                    continue
                if re.search('#?\s*include', rule) or re.search('#?\s*include', entry):
                    continue
                #Check if the rule implies entry
                if apparmor.matchliteral(rule, entry):
                    #Check the modes
                    cm = profile[allow]['path'][rule]['mode']
                    am = profile[allow]['path'][rule]['audit']
                    #If modes of rule are a superset of rules implied by entry we can safely remove it
                    if apparmor.mode_contains(cm, profile_other[allow]['path'][entry]['mode']) and apparmor.mode_contains(am, profile_other[allow]['path'][entry]['audit']):           
                        deleted.append(entry)
        #print(deleted)
        for entry in deleted:
            profile_other[allow]['path'].pop(entry)
        return len(deleted)
    

    def match_include_to_path(incname, allow, path):
        combinedmode = set()
        combinedaudit = set()
        matches = []
        includelist = [incname]
        while includelist:
            incfile = str(includelist.pop(0))
            ret = load_include(incfile)
            if not include.get(incfile,{}):
                continue
            cm, am, m = rematchfrag(include[incfile].get(incfile, {}), allow, path)
            #print(incfile, cm, am, m)
            if cm:
                combinedmode |= cm
                combinedaudit |= am
                matches += m
            
            if include[incfile][incfile][allow]['path'][path]:
                combinedmode |= include[incfile][incfile][allow]['path'][path]['mode']
                combinedaudit |= include[incfile][incfile][allow]['path'][path]['audit']
            
            if include[incfile][incfile]['include'].keys():
                includelist += include[incfile][incfile]['include'].keys()
                
        return combinedmode, combinedaudit, matches
    
    def use_autodep(self, program):
        apparmor.check_qualifiers(program)           
        
        if os.path.exists(apparmor.get_profile_filename(program) and not self.force):
            apparmor.UI_Info('Profile for %s already exists - skipping.'%program)
        else:
            apparmor.autodep(program)
            if self.aa_mountpoint:
                apparmor.reload(program)
    
    def enable_profile(self, filename): 
        apparmor.delete_symlink('disable', filename)
        
    def disable_profile(self, filename):
        apparmor.create_symlink('disable', filename)