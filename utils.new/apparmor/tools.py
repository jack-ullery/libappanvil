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
import gettext
import os
import sys

import apparmor.aa as apparmor
from apparmor.common import user_perm

# setup module translations
from apparmor.translations import init_translation
_ = init_translation()

class aa_tools:
    def __init__(self, tool_name, args):
        self.name = tool_name
        self.profiledir = args.dir
        self.profiling = args.program
        self.check_profile_dir()
        self.silent = None

        if tool_name in ['audit', 'complain']:
            self.remove = args.remove
        elif tool_name == 'disable':
            self.revert = args.revert
            self.disabledir = apparmor.profile_dir + '/disable'
            self.check_disable_dir()
        elif tool_name == 'autodep':
            self.force = args.force
            self.aa_mountpoint = apparmor.check_for_apparmor()
        elif tool_name == 'cleanprof':
            self.silent = args.silent

    def check_profile_dir(self):
        if self.profiledir:
            apparmor.profile_dir = apparmor.get_full_path(self.profiledir)
            if not os.path.isdir(apparmor.profile_dir):
                raise apparmor.AppArmorException("%s is not a directory." % self.profiledir)

        if not user_perm(apparmor.profile_dir):
            raise apparmor.AppArmorException("Cannot write to profile directory: %s" % (apparmor.profile_dir))

    def check_disable_dir(self):
        if not os.path.isdir(self.disabledir):
            raise apparmor.AppArmorException("Can't find AppArmor disable directory %s" % self.disabledir)

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

            apparmor.read_profiles()
            #If program does not exists on the system but its profile does
            if not program and apparmor.profile_exists(p):
                program = p

            if not program or not(os.path.exists(program) or apparmor.profile_exists(program)):
                if program and not program.startswith('/'):
                    program = apparmor.UI_GetString(_('The given program cannot be found, please try with the fully qualified path name of the program: '), '')
                else:
                    apparmor.UI_Info(_("%s does not exist, please double-check the path.") % p)
                    sys.exit(1)

            if self.name == 'autodep' and program and os.path.exists(program):
                self.use_autodep(program)

            elif program and apparmor.profile_exists(program):
                if self.name == 'cleanprof':
                    self.clean_profile(program, p)

                else:
                    filename = apparmor.get_profile_filename(program)

                    if not os.path.isfile(filename) or apparmor.is_skippable_file(filename):
                        apparmor.UI_Info(_('Profile for %s not found, skipping') % p)

                    elif self.name == 'disable':
                        if not self.revert:
                            apparmor.UI_Info(_('Disabling %s.') % program)
                            self.disable_profile(filename)
                        else:
                            apparmor.UI_Info(_('Enabling %s.') % program)
                            self.enable_profile(filename)

                    elif self.name == 'audit':
                        if not self.remove:
                            apparmor.UI_Info(_('Setting %s to audit mode.') % program)
                        else:
                            apparmor.UI_Info(_('Removing audit mode from %s.') % program)
                        apparmor.change_profile_flags(filename, program, 'audit', not self.remove)

                    elif self.name == 'complain':
                        if not self.remove:
                            apparmor.set_complain(filename, program)
                        else:
                            apparmor.set_enforce(filename, program)
                        #apparmor.set_profile_flags(filename, self.name)
                    else:
                        # One simply does not walk in here!
                        raise apparmor.AppArmorException('Unknown tool: %s' % self.name)

                    cmd_info = apparmor.cmd([apparmor.parser, filename, '-I%s' % apparmor.profile_dir, '-R 2>&1', '1>/dev/null'])
                    #cmd_info = apparmor.cmd(['cat', filename, '|', apparmor.parser, '-I%s'%apparmor.profile_dir, '-R 2>&1', '1>/dev/null'])

                    if cmd_info[0] != 0:
                        raise apparmor.AppArmorException(cmd_info[1])

            else:
                if '/' not in p:
                    apparmor.UI_Info(_("Can't find %s in the system path list. If the name of the application\nis correct, please run 'which %s' as a user with correct PATH\nenvironment set up in order to find the fully-qualified path and\nuse the full path as parameter.") % (p, p))
                else:
                    apparmor.UI_Info(_("%s does not exist, please double-check the path.") % p)
                    sys.exit(1)

    def clean_profile(self, program, p):
        filename = apparmor.get_profile_filename(program)
        import apparmor.cleanprofile as cleanprofile
        prof = cleanprofile.Prof(filename)
        cleanprof = cleanprofile.CleanProf(True, prof, prof)
        deleted = cleanprof.remove_duplicate_rules(program)
        apparmor.UI_Info(_("\nDeleted %s rules.") % deleted)
        apparmor.changed[program] = True

        if filename:
            if not self.silent:
                q = apparmor.hasher()
                q['title'] = 'Changed Local Profiles'
                q['headers'] = []
                q['explanation'] = _('The local profile for %s in file %s was changed. Would you like to save it?') % (program, filename)
                q['functions'] = ['CMD_SAVE_CHANGES', 'CMD_VIEW_CHANGES', 'CMD_ABORT']
                q['default'] = 'CMD_VIEW_CHANGES'
                q['options'] = []
                q['selected'] = 0
                p = None
                ans = ''
                arg = None
                while ans != 'CMD_SAVE_CHANGES':
                    ans, arg = apparmor.UI_PromptUser(q)
                    if ans == 'CMD_SAVE_CHANGES':
                        apparmor.write_profile_ui_feedback(program)
                        apparmor.reload_base(program)
                    elif ans == 'CMD_VIEW_CHANGES':
                        #oldprofile = apparmor.serialize_profile(apparmor.original_aa[program], program, '')
                        newprofile = apparmor.serialize_profile(apparmor.aa[program], program, '')
                        apparmor.display_changes_with_comments(filename, newprofile)
            else:
                apparmor.write_profile_ui_feedback(program)
                apparmor.reload_base(program)
        else:
            raise apparmor.AppArmorException(_('The profile for %s does not exists. Nothing to clean.') % p)

    def use_autodep(self, program):
        apparmor.check_qualifiers(program)

        if os.path.exists(apparmor.get_profile_filename(program) and not self.force):
            apparmor.UI_Info('Profile for %s already exists - skipping.' % program)
        else:
            apparmor.autodep(program)
            if self.aa_mountpoint:
                apparmor.reload(program)

    def enable_profile(self, filename):
        apparmor.delete_symlink('disable', filename)

    def disable_profile(self, filename):
        apparmor.create_symlink('disable', filename)
