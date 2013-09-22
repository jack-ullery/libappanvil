import re
import copy

import apparmor

class Prof:
    def __init__(self, filename):
        self.aa = apparmor.aa.aa
        self.filelist = apparmor.aa.filelist
        self.include = apparmor.aa.include
        self.filename = filename
        
class CleanProf:
    def __init__(self, same_file, profile, other):
        #If same_file we're basically comparing the file against itself to check superfluous rules
        self.same_file = same_file
        self.profile = profile
        self.other = profile
    
    def compare_profiles(self):
        #Remove the duplicate file-level includes from other
        other_file_includes = list(self.other.profile.filename['include'].keys())
        for rule in self.profile.filelist[self.profile.filename]:
            if rule in other_file_includes:
                self.other.other.filename['include'].pop(rule)
        
        for profile in self.profile.aa.keys():
            self.remove_duplicate_rules(profile)
        
    def remove_duplicate_rules(self, program):
        #Process the profile of the program
        #Process every hat in the profile individually
        file_includes = list(self.profile.filelist[self.profile.filename]['include'].keys())
        deleted = 0
        for hat in self.profile.aa[program].keys():
            #The combined list of includes from profile and the file
            includes = list(self.profile.aa[program][hat]['include'].keys()) + file_includes
     
            #Clean up superfluous rules from includes in the other profile         
            for inc in includes:
                if not self.profile.include.get(inc, {}).get(inc,False):
                    apparmor.aa.load_include(inc)
                deleted += apparmor.aa.delete_duplicates(self.other.aa[program][hat], inc)
            
            #Clean the duplicates of caps in other profile
            deleted += self.delete_cap_duplicates(self.profile.aa[program][hat]['allow']['capability'], self.other.aa[program][hat]['allow']['capability'], self.same_file)         
            deleted += self.delete_cap_duplicates(self.profile.aa[program][hat]['deny']['capability'], self.other.aa[program][hat]['deny']['capability'], self.same_file)

            #Clean the duplicates of path in other profile
            deleted += self.delete_path_duplicates(self.profile.aa[program][hat], self.other.aa[program][hat], 'allow', self.same_file)
            deleted += self.delete_path_duplicates(self.profile.aa[program][hat], self.other.aa[program][hat], 'deny', self.same_file)
            
            #Clean the duplicates of net rules in other profile
            deleted += self.delete_net_duplicates(self.profile.aa[program][hat]['allow']['netdomain'], self.other.aa[program][hat]['allow']['netdomain'], self.same_file)
            deleted += self.delete_net_duplicates(self.profile.aa[program][hat]['deny']['netdomain'], self.other.aa[program][hat]['deny']['netdomain'], self.same_file)
            
            return deleted

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
                if apparmor.aa.matchliteral(rule, entry):
                    #Check the modes
                    cm = profile[allow]['path'][rule]['mode']
                    am = profile[allow]['path'][rule]['audit']
                    #If modes of rule are a superset of rules implied by entry we can safely remove it
                    if apparmor.aa.mode_contains(cm, profile_other[allow]['path'][entry]['mode']) and apparmor.aa.mode_contains(am, profile_other[allow]['path'][entry]['audit']):           
                        deleted.append(entry)

        for entry in deleted:
            profile_other[allow]['path'].pop(entry)

        return len(deleted)
    
    def delete_cap_duplicates(self, profilecaps, profilecaps_other, same_profile=True):
        deleted = []
        if profilecaps and profilecaps_other and not same_profile:
            for capname in profilecaps.keys():
                if profilecaps_other[capname].get('set', False):
                    deleted.append(capname)
            for capname in deleted:
                profilecaps_other.pop(capname)
        
        return len(deleted)
    
    def delete_net_duplicates(self, netrules, netrules_other, same_profile=True):
        deleted = 0
        copy_netrules_other = copy.deepcopy(netrules_other)
        if netrules_other and netrules:
            netglob = False
            # Delete matching rules
            if netrules.get('all', False):
                netglob = True
            #Iterate over a copy of the rules in the other profile
            for fam in copy_netrules_other.keys():
                if netglob or (type(netrules['rule'][fam]) != dict and netrules['rule'][fam]):
                    if not same_profile:
                        if type(netrules_other['rule'][fam] == dict):
                            deleted += len(netrules['rule'][fam].keys())
                        else:
                            deleted += 1
                        netrules_other['rule'].pop(fam)    
                elif type(netrules_other['rule'][fam]) != dict and netrules_other['rule'][fam]:
                    if type(netrules['rule'][fam]) != dict and netrules['rule'][fam]:
                        if not same_profile:
                            netrules_other['rule'].pop(fam)
                            deleted += 1
                else:
                    for sock_type in netrules_other['rule'][fam].keys():
                        if netrules['rule'].get(fam, False):
                            if netrules['rule'][fam].get(sock_type, False):
                                if not same_profile:
                                    netrules_other['rule'][fam].pop(sock_type)
                                    deleted += 1
        return deleted