# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
# ----------------------------------------------------------------------
import re

import apparmor

class Prof(object):
    def __init__(self, filename):
        self.aa = apparmor.aa.aa
        self.filelist = apparmor.aa.filelist
        self.include = apparmor.aa.include
        self.filename = filename

class CleanProf(object):
    def __init__(self, same_file, profile, other):
        #If same_file we're basically comparing the file against itself to check superfluous rules
        self.same_file = same_file
        self.profile = profile
        self.other = other

    def compare_profiles(self):
        deleted = 0
        other_file_includes = list(self.other.filelist[self.other.filename]['include'].keys())

        #Remove the duplicate file-level includes from other
        for rule in self.profile.filelist[self.profile.filename]['include'].keys():
            if rule in other_file_includes:
                self.other.filelist[self.other.filename]['include'].pop(rule)

        for profile in self.profile.aa.keys():
            deleted += self.remove_duplicate_rules(profile)

        return deleted

    def remove_duplicate_rules(self, program):
        #Process the profile of the program
        #Process every hat in the profile individually
        file_includes = list(self.profile.filelist[self.profile.filename]['include'].keys())
        deleted = 0
        for hat in self.profile.aa[program].keys():
            #The combined list of includes from profile and the file
            includes = list(self.profile.aa[program][hat]['include'].keys()) + file_includes

            #If different files remove duplicate includes in the other profile
            if not self.same_file:
                for inc in includes:
                    if self.other.aa[program][hat]['include'].get(inc, False):
                        self.other.aa[program][hat]['include'].pop(inc)
                        deleted += 1
            #Clean up superfluous rules from includes in the other profile
            for inc in includes:
                if not self.profile.include.get(inc, {}).get(inc, False):
                    apparmor.aa.load_include(inc)
                deleted += apparmor.aa.delete_duplicates(self.other.aa[program][hat], inc)

            #Clean the duplicates of caps in other profile
            deleted += delete_cap_duplicates(self.profile.aa[program][hat]['allow']['capability'], self.other.aa[program][hat]['allow']['capability'], self.same_file)
            deleted += delete_cap_duplicates(self.profile.aa[program][hat]['deny']['capability'], self.other.aa[program][hat]['deny']['capability'], self.same_file)

            #Clean the duplicates of path in other profile
            deleted += delete_path_duplicates(self.profile.aa[program][hat], self.other.aa[program][hat], 'allow', self.same_file)
            deleted += delete_path_duplicates(self.profile.aa[program][hat], self.other.aa[program][hat], 'deny', self.same_file)

            #Clean the duplicates of net rules in other profile
            deleted += delete_net_duplicates(self.profile.aa[program][hat]['allow']['netdomain'], self.other.aa[program][hat]['allow']['netdomain'], self.same_file)
            deleted += delete_net_duplicates(self.profile.aa[program][hat]['deny']['netdomain'], self.other.aa[program][hat]['deny']['netdomain'], self.same_file)

            return deleted

def delete_path_duplicates(profile, profile_other, allow, same_profile=True):
    deleted = []
    # Check if any individual rule makes any rule superfluous
    for rule in profile[allow]['path'].keys():
        for entry in profile_other[allow]['path'].keys():
            if rule == entry:
                # Check the modes
                cm = profile[allow]['path'][rule]['mode']
                am = profile[allow]['path'][rule]['audit']
                # If modes of rule are a superset of rules implied by entry we can safely remove it
                if apparmor.aa.mode_contains(cm, profile_other[allow]['path'][entry]['mode']) and apparmor.aa.mode_contains(am, profile_other[allow]['path'][entry]['audit']):
                    if not same_profile:
                        deleted.append(entry)
                continue
            if re.search('#?\s*include', rule) or re.search('#?\s*include', entry):
                continue
            # Check if the rule implies entry
            if apparmor.aa.matchliteral(rule, entry):
                # Check the modes
                cm = profile[allow]['path'][rule]['mode']
                am = profile[allow]['path'][rule]['audit']
                # If modes of rule are a superset of rules implied by entry we can safely remove it
                if apparmor.aa.mode_contains(cm, profile_other[allow]['path'][entry]['mode']) and apparmor.aa.mode_contains(am, profile_other[allow]['path'][entry]['audit']):
                    deleted.append(entry)

    for entry in deleted:
        profile_other[allow]['path'].pop(entry)

    return len(deleted)

def delete_cap_duplicates(profilecaps, profilecaps_other, same_profile=True):
    deleted = []
    if profilecaps and profilecaps_other and not same_profile:
        for capname in profilecaps.keys():
            if profilecaps_other[capname].get('set', False):
                deleted.append(capname)
        for capname in deleted:
            profilecaps_other.pop(capname)

    return len(deleted)

def delete_net_duplicates(netrules, netrules_other, same_profile=True):
    deleted = 0
    hasher_obj = apparmor.aa.hasher()
    if netrules_other and netrules:
        netglob = False
        # Delete matching rules
        if netrules.get('all', False):
            netglob = True
        # Iterate over a copy of the rules in the other profile
        for fam in list(netrules_other['rule'].keys()):
            if netglob or (type(netrules['rule'][fam]) != type(hasher_obj) and netrules['rule'][fam]):
                if not same_profile:
                    if type(netrules_other['rule'][fam]) == type(hasher_obj):
                        deleted += len(netrules_other['rule'][fam].keys())
                    else:
                        deleted += 1
                    netrules_other['rule'].pop(fam)
            elif type(netrules_other['rule'][fam]) != type(hasher_obj) and netrules_other['rule'][fam]:
                if type(netrules['rule'][fam]) != type(hasher_obj) and netrules['rule'][fam]:
                    if not same_profile:
                        netrules_other['rule'].pop(fam)
                        deleted += 1
            else:
                for sock_type in list(netrules_other['rule'][fam].keys()):
                    if netrules['rule'].get(fam, False):
                        if netrules['rule'][fam].get(sock_type, False):
                            if not same_profile:
                                netrules_other['rule'][fam].pop(sock_type)
                                deleted += 1
    return deleted
