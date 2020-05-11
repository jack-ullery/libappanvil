# ----------------------------------------------------------------------
#    Copyright (C) 2018-2020 Christian Boltz <apparmor@cboltz.de>
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

from apparmor.aare import AARE
from apparmor.common import AppArmorBug, AppArmorException, type_is_str
from apparmor.rule import quote_if_needed
from apparmor.rule.abi import AbiRule, AbiRuleset
from apparmor.rule.include import IncludeRule, IncludeRuleset

# setup module translations
from apparmor.translations import init_translation
_ = init_translation()


class ProfileList:
    ''' Stores the preamble section and the list of profile(s) (both name and
        attachment) that live in profile files.

        Also allows "reverse" lookups to find out in which file a profile
        lives.
    '''

    def __init__(self):
        self.profile_names = {}     # profile name -> filename
        self.attachments = {}       # attachment -> filename
        self.attachments_AARE = {}  # AARE(attachment) -> filename
        self.files = {}             # filename -> content - see init_file()

    def init_file(self, filename):
        if self.files.get(filename):
            return  # don't re-initialize / overwrite existing data

        self.files[filename] = {
            'abi': AbiRuleset(),
            'alias': {},
            'include': {},  # not filled, but avoids errors in is_known_rule() and some other functions when aa-mergeprof asks about the preamble
            'inc_ie': IncludeRuleset(),
            'profiles': [],
        }

    def add_profile(self, filename, profile_name, attachment):
        ''' Add the given profile and attachment to the list '''

        if not filename:
            raise AppArmorBug('Empty filename given to ProfileList')

        if not profile_name and not attachment:
            raise AppArmorBug('Neither profile name or attachment given')

        if profile_name in self.profile_names:
            raise AppArmorException(_('Profile %(profile_name)s exists in %(filename)s and %(filename2)s' % {'profile_name': profile_name, 'filename': filename, 'filename2': self.profile_names[profile_name]}))

        if attachment in self.attachments:
            raise AppArmorException(_('Profile for %(profile_name)s exists in %(filename)s and %(filename2)s' % {'profile_name': attachment, 'filename': filename, 'filename2': self.attachments[attachment]}))

        if profile_name:
            self.profile_names[profile_name] = filename

        if attachment:
            self.attachments[attachment] = filename
            self.attachments_AARE[attachment] = AARE(attachment, True)

        self.init_file(filename)

        if profile_name:
            self.files[filename]['profiles'].append(profile_name)
        else:
            self.files[filename]['profiles'].append(attachment)

    def add_abi(self, filename, abi_rule):
        ''' Store the given abi rule for the given profile filename preamble '''

        if type(abi_rule) is not AbiRule:
            raise AppArmorBug('Wrong type given to ProfileList: %s' % abi_rule)

        self.init_file(filename)

        self.files[filename]['abi'].add(abi_rule)

    def add_alias(self, filename, alias, target):
        ''' Store the given alias rule for the given profile filename preamble '''

        if not type_is_str(alias):
            raise AppArmorBug('Wrong type given to ProfileList: %s' % alias)
        if not type_is_str(target):
            raise AppArmorBug('Wrong type given to ProfileList: %s' % target)

        self.init_file(filename)

        # allowed in the parser
        # if self.files[filename]['alias'].get(alias):
        #     raise AppArmorException('Trying to re-define alias %s' % alias)

        self.files[filename]['alias'][alias] = target

    def add_inc_ie(self, filename, inc_rule):
        ''' Store the given include / include if exists rule for the given profile filename preamble '''
        if type(inc_rule) is not IncludeRule:
            raise AppArmorBug('Wrong type given to ProfileList: %s' % inc_rule)

        self.init_file(filename)

        self.files[filename]['inc_ie'].add(inc_rule)

    def get_raw(self, filename, depth=0):
        ''' Get the preamble for the given profile filename (in original formatting) '''
        if not self.files.get(filename):
            raise AppArmorBug('%s not listed in ProfileList files' % filename)

        data = []
        data += self.files[filename]['abi'].get_raw(depth)
        data += write_alias(self.files[filename])
        data += self.files[filename]['inc_ie'].get_raw(depth)
        return data

    def get_clean(self, filename, depth=0):
        ''' Get the preamble for the given profile filename (in clean formatting) '''
        if not self.files.get(filename):
            raise AppArmorBug('%s not listed in ProfileList files' % filename)

        data = []
        # commented out for now because abi rules need to be written first - for now, use get_clean_first() instead
        # data += self.files[filename]['abi'].get_clean_unsorted(depth)
        # data += write_alias(self.files[filename])
        data += self.files[filename]['inc_ie'].get_clean_unsorted(depth)
        return data

    def get_clean_first(self, filename, depth=0):
        ''' Get preamble rules for the given profile filename (in clean formatting) that need to be at the beginning.
            This is a temporary function, and will be dropped / merged with get_clean() when the whole preamble is moved to ProfileList
            '''
        if not self.files.get(filename):
            raise AppArmorBug('%s not listed in ProfileList files' % filename)

        data = []
        data += self.files[filename]['abi'].get_clean_unsorted(depth)
        data += write_alias(self.files[filename])
        return data

    def filename_from_profile_name(self, name):
        ''' Return profile filename for the given profile name, or None '''

        return self.profile_names.get(name, None)

    def filename_from_attachment(self, attachment):
        ''' Return profile filename for the given attachment/executable path, or None '''

        if not attachment.startswith( ('/', '@', '{') ):
            raise AppArmorBug('Called filename_from_attachment with non-path attachment: %s' % attachment)

        # plain path
        if self.attachments.get(attachment):
            return self.attachments[attachment]

        # try AARE matches to cover profile names with alternations and wildcards
        for path in self.attachments.keys():
            if self.attachments_AARE[path].match(attachment):
                return self.attachments[path]  # XXX this returns the first match, not necessarily the best one

        return None  # nothing found

    def profiles_in_file(self, filename):
        ''' Return list of profiles in the given file '''
        if not self.files.get(filename):
            raise AppArmorBug('%s not listed in ProfileList files' % filename)

        return self.files[filename]['profiles']

def write_alias(prof_data):
    data = []

    if prof_data['alias']:
        for key in sorted(prof_data['alias'].keys()):
            data.append('alias %s -> %s,' % (quote_if_needed(key), quote_if_needed(prof_data['alias'][key])))

        data.append('')

    return data
