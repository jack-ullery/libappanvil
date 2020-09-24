# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#    Copyright (C) 2014-2017 Christian Boltz <apparmor@cboltz.de>
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


from apparmor.common import AppArmorBug, type_is_str

from apparmor.rule.abi              import AbiRuleset
from apparmor.rule.capability       import CapabilityRuleset
from apparmor.rule.change_profile   import ChangeProfileRuleset
from apparmor.rule.dbus             import DbusRuleset
from apparmor.rule.file             import FileRuleset
from apparmor.rule.include          import IncludeRuleset
from apparmor.rule.network          import NetworkRuleset
from apparmor.rule.ptrace           import PtraceRuleset
from apparmor.rule.rlimit           import RlimitRuleset
from apparmor.rule.signal           import SignalRuleset

from apparmor.rule import quote_if_needed

# setup module translations
from apparmor.translations import init_translation
_ = init_translation()

ruletypes = {
    'abi':              {'ruleset': AbiRuleset},
    'inc_ie':           {'ruleset': IncludeRuleset},
    'capability':       {'ruleset': CapabilityRuleset},
    'change_profile':   {'ruleset': ChangeProfileRuleset},
    'dbus':             {'ruleset': DbusRuleset},
    'file':             {'ruleset': FileRuleset},
    'network':          {'ruleset': NetworkRuleset},
    'ptrace':           {'ruleset': PtraceRuleset},
    'rlimit':           {'ruleset': RlimitRuleset},
    'signal':           {'ruleset': SignalRuleset},
}

class ProfileStorage:
    '''class to store the content (header, rules, comments) of a profilename

       Acts like a dict(), but has some additional checks.
    '''

    def __init__(self, profilename, hat, calledby):
        data = dict()

        # self.data['info'] isn't used anywhere, but can be helpful in debugging.
        data['info'] = {'profile': profilename, 'hat': hat, 'calledby': calledby}

        for rule in ruletypes:
            data[rule] = ruletypes[rule]['ruleset']()

        data['filename']         = ''
        data['logprof_suggest']  = ''  # set in abstractions that should be suggested by aa-logprof
        data['name']             = ''
        data['attachment']       = ''
        data['xattrs']           = ''
        data['flags']            = ''
        data['external']         = False
        data['header_comment']   = ''  # currently only set by change_profile_flags()
        data['initial_comment']  = ''
        data['profile_keyword']  = False  # currently only set by change_profile_flags()
        data['profile']          = False  # profile or hat?

        data['allow'] = dict()
        data['deny'] = dict()

        # mount, pivot_root, unix have a .get() fallback to list() - initialize them nevertheless
        data['allow']['mount']   = list()
        data['deny']['mount']    = list()
        data['allow']['pivot_root'] = list()
        data['deny']['pivot_root']  = list()
        data['allow']['unix']    = list()
        data['deny']['unix']     = list()

        self.data = data

    def __getitem__(self, key):
        if key in self.data:
            return self.data[key]
        else:
            raise AppArmorBug('attempt to read unknown key %s' % key)

    def __setitem__(self, key, value):
        if key not in self.data:
            raise AppArmorBug('attempt to set unknown key %s' % key)

        # allow writing bool values
        if type(self.data[key]) == bool:
            if type(value) == bool:
                self.data[key] = value
            else:
                raise AppArmorBug('Attempt to change type of "%s" from %s to %s, value %s' % (key, type(self.data[key]), type(value), value))

        # allow writing str or None to some keys
        elif key in ('xattrs', 'flags', 'filename'):
            if type_is_str(value) or value is None:
                self.data[key] = value
            else:
                raise AppArmorBug('Attempt to change type of "%s" from %s to %s, value %s' % (key, type(self.data[key]), type(value), value))

        # allow writing str values
        elif type_is_str(self.data[key]):
            if type_is_str(value):
                self.data[key] = value
            else:
                raise AppArmorBug('Attempt to change type of "%s" from %s to %s, value %s' % (key, type(self.data[key]), type(value), value))

        # don't allow overwriting of other types
        else:
            raise AppArmorBug('Attempt to overwrite "%s" with %s, type %s' % (key, value, type(value)))

    def __repr__(self):
        return('\n<ProfileStorage>\n%s\n</ProfileStorage>\n' % '\n'.join(self.get_rules_clean(1)))

    def get(self, key, fallback=None):
        if key in self.data:
            return self.data.get(key, fallback)
        else:
            raise AppArmorBug('attempt to read unknown key %s' % key)

    def get_rules_clean(self, depth):
        '''return all clean rules of a profile (with default formatting, and leading whitespace as specified in the depth parameter)

           Note that the profile header and the closing "}" are _not_ included.
        '''

        # "old" write functions for rule types not implemented as *Rule class yet
        write_functions = {
            'mount': write_mount,
            'pivot_root': write_pivot_root,
            'unix': write_unix,
        }

        write_order = [
            'abi',
            'inc_ie',
            'rlimit',
            'capability',
            'network',
            'dbus',
            'mount',
            'signal',
            'ptrace',
            'pivot_root',
            'unix',
            'file',
            'change_profile',
        ]

        data = []

        for ruletype in write_order:
            if write_functions.get(ruletype):
                data += write_functions[ruletype](self.data, depth)
            else:
                data += self.data[ruletype].get_clean(depth)

        return data


def split_flags(flags):
    '''split the flags given as string into a sorted, de-duplicated list'''

    if flags is None:
        flags = ''

    # Flags may be whitespace and/or comma separated
    flags_list = flags.replace(',', ' ').split()
    # sort and remove duplicates
    return sorted(set(flags_list))

def add_or_remove_flag(flags, flags_to_change, set_flag):
    '''add (if set_flag == True) or remove the given flags_to_change to flags'''

    if type_is_str(flags) or flags is None:
        flags = split_flags(flags)

    if type_is_str(flags_to_change) or flags_to_change is None:
        flags_to_change = split_flags(flags_to_change)

    if set_flag:
        for flag_to_change in flags_to_change:
            if flag_to_change not in flags:
                flags.append(flag_to_change)
    else:
        for flag_to_change in flags_to_change:
            if flag_to_change in flags:
                flags.remove(flag_to_change)

    return sorted(flags)


def var_transform(ref):
    data = []
    for value in sorted(ref):
        if not value:
            value = '""'
        data.append(quote_if_needed(value))
    return ' '.join(data)

def write_mount_rules(prof_data, depth, allow):
    pre = '  ' * depth
    data = []

    # no mount rules, so return
    if not prof_data[allow].get('mount', False):
        return data

    for mount_rule in prof_data[allow]['mount']:
        data.append('%s%s' % (pre, mount_rule.serialize()))
    data.append('')
    return data

def write_mount(prof_data, depth):
    data = write_mount_rules(prof_data, depth, 'deny')
    data += write_mount_rules(prof_data, depth, 'allow')
    return data

def write_pivot_root_rules(prof_data, depth, allow):
    pre = '  ' * depth
    data = []

    # no pivot_root rules, so return
    if not prof_data[allow].get('pivot_root', False):
        return data

    for pivot_root_rule in prof_data[allow]['pivot_root']:
        data.append('%s%s' % (pre, pivot_root_rule.serialize()))
    data.append('')
    return data

def write_pivot_root(prof_data, depth):
    data = write_pivot_root_rules(prof_data, depth, 'deny')
    data += write_pivot_root_rules(prof_data, depth, 'allow')
    return data

def write_unix(prof_data, depth):
    data = write_unix_rules(prof_data, depth, 'deny')
    data += write_unix_rules(prof_data, depth, 'allow')
    return data

def write_unix_rules(prof_data, depth, allow):
    pre = '  ' * depth
    data = []

    # no unix rules, so return
    if not prof_data[allow].get('unix', False):
        return data

    for unix_rule in prof_data[allow]['unix']:
        data.append('%s%s' % (pre, unix_rule.serialize()))
    data.append('')
    return data
