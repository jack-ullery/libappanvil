import os
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
        self.delete_superluous_rules(program)
        if filename:
            apparmor.write_profile_ui_feedback(program)
            apparmor.reload_base(program)
        else:
            raise apparmor.AppArmorException(_('The profile for %s does not exists. Nothing to clean.')%p)
    
    def delete_superluous_rules(self, program):
        #print(filename, apparmor.aa.get(program, False))
        #print(apparmor.aa[program][program]['include'])
        includes = apparmor.aa[program][program]['include'].keys()
        allow_path_rules = list(apparmor.aa[program][program]['allow']['path'].keys())
        allow_net_rules =  list(apparmor.aa[program][program]['allow']['netdomain']['rule'].keys())
        #b=set(allow_rules)
        #print(allow_rules)
        dele = 0
        #print(includes)
        
        #Clean up superfluous rules from includes
        #print(apparmor.include.keys())
        
        for inc in includes:
            #old=dele
            if not apparmor.include.get(inc, False):
                apparmor.load_include(inc)
            dele+= apparmor.delete_duplicates(apparmor.aa[program][program], inc)
            #dele+= apparmor.delete_path_duplicates(apparmor.aa[program][program], str(inc), 'allow')
            #if dele>old:
            #    print(inc)
        
        for rule in allow_path_rules:
            pass
        print(dele)
        #allow_rules = [] + list(apparmor.aa[program][program]['allow']['path'].keys())
        #allow_rules +=  list(apparmor.aa[program][program]['allow']['netdomain']['rule'].keys()) + list(apparmor.aa[program][program]['allow']['capability'].keys()) 
        #c=set(allow_rules)
        #print(b.difference(c))
        sys.exit(0)

    def delete_path_duplicates(profile, incname, allow):
        deleted = []
        for entry in profile[allow]['path'].keys():
            if entry == '#include <%s>'%incname:
                continue
            cm, am, m = match_include_to_path(incname, allow, entry)
            if cm and mode_contains(cm, profile[allow]['path'][entry]['mode']) and mode_contains(am, profile[allow]['path'][entry]['audit']):
                deleted.append(entry)
        
        for entry in deleted:
            profile[allow]['path'].pop(entry)
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