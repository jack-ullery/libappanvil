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


from apparmor.common import AppArmorBug, AppArmorException, type_is_str

from apparmor.rule.capability       import CapabilityRuleset
from apparmor.rule.change_profile   import ChangeProfileRuleset
from apparmor.rule.dbus             import DbusRuleset
from apparmor.rule.file             import FileRuleset
from apparmor.rule.network          import NetworkRuleset
from apparmor.rule.ptrace           import PtraceRuleset
from apparmor.rule.rlimit           import RlimitRuleset
from apparmor.rule.signal           import SignalRuleset

from apparmor.rule import quote_if_needed

# setup module translations
from apparmor.translations import init_translation
_ = init_translation()

ruletypes = {
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

        data['alias']            = dict()
        data['abi']              = []
        data['include']          = dict()
        data['localinclude']     = dict()
        data['lvar']             = dict()
        data['repo']             = dict()

        data['filename']         = ''
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
        # TODO: Most of the keys (containing *Ruleset, dict() or list()) should be read-only.
        #       Their content needs to be changed, but the container shouldn't
        #       Note: serialize_profile_from_old_profile.write_prior_segments() and write_prior_segments() expect the container to be writeable!
        # TODO: check if value has the expected type
        if key in self.data:
            self.data[key] = value
        else:
            raise AppArmorBug('attempt to set unknown key %s' % key)

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
            'abi': write_abi,
            'alias': write_alias,
            'include': write_includes,
            'lvar': write_list_vars,
            'mount': write_mount,
            'pivot_root': write_pivot_root,
            'unix': write_unix,
        }

        write_order = [
            'abi',
            'alias',
            'lvar',
            'include',
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

def add_or_remove_flag(flags, flag_to_change, set_flag):
    '''add (if set_flag == True) or remove the given flag_to_change to flags'''

    if type_is_str(flags) or flags is None:
        flags = split_flags(flags)

    if set_flag:
        if flag_to_change not in flags:
            flags.append(flag_to_change)
    else:
        if flag_to_change in flags:
            flags.remove(flag_to_change)

    return sorted(flags)


def set_allow_str(allow):
    if allow == 'deny':
        return 'deny '
    elif allow == 'allow':
        return ''
    elif allow == '':
        return ''
    else:
        raise AppArmorException(_("Invalid allow string: %(allow)s"))

def write_list_vars(ref, depth):
    name = 'lvar'
    pre = '  ' * depth
    data = []

    if ref.get(name, False):
        for key in sorted(ref[name].keys()):
            value = var_transform(ref[name][key])
            data.append('%s%s = %s' % (pre, key, value))
        if ref[name].keys():
            data.append('')

    return data

def write_abi(ref, depth):
    pre = '  ' * depth
    data = []

    if ref.get('abi'):
        for line in ref.get('abi'):
            data.append('%s%s' % (pre, line))
        data.append('')

    return data

def write_alias(prof_data, depth):
    pre = '  ' * depth
    data = []

    if prof_data['alias']:
        for key in sorted(prof_data['alias'].keys()):
            data.append('%salias %s -> %s,' % (pre, quote_if_needed(key), quote_if_needed(prof_data['alias'][key])))

        data.append('')

    return data

def write_includes(prof_data, depth):
    pre = '  ' * depth
    data = []

    for key in sorted(prof_data['include'].keys()):
        if key.startswith('/'):
            qkey = '"%s"' % key
        else:
            qkey = '<%s>' % quote_if_needed(key)

        data.append('%s#include %s' % (pre, qkey))

    if data:
        data.append('')

    return data

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
