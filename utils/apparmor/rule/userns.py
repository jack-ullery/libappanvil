# ----------------------------------------------------------------------
#    Copyright (C) 2022 Canonical, Ltd.
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

from apparmor.regex import RE_PROFILE_USERNS
from apparmor.common import AppArmorBug, AppArmorException
from apparmor.rule import BaseRule, BaseRuleset, check_and_split_list, logprof_value_or_all, parse_modifiers

# setup module translations
from apparmor.translations import init_translation
_ = init_translation()

access_keyword = 'create'

RE_USERNS_DETAILS = re.compile(
    '^' +
    r'\s+(?P<access>' + access_keyword + ')?' +  # optional access keyword
    r'\s*$')


class UserNamespaceRule(BaseRule):
    '''Class to handle and store a single userns rule'''

    # Nothing external should reference this class, all external users
    # should reference the class field UserNamespaceRule.ALL
    class __UserNamespaceAll(object):
        pass

    ALL = __UserNamespaceAll

    rule_name = 'userns'

    def __init__(self, access, audit=False, deny=False,
                 allow_keyword=False, comment='', log_event=None):

        super().__init__(audit=audit, deny=deny,
                         allow_keyword=allow_keyword,
                         comment=comment,
                         log_event=log_event)

        self.access, self.all_access, unknown_items = check_and_split_list(access, access_keyword, self.ALL, type(self).__name__, 'access')
        if unknown_items:
            raise AppArmorException(_('Passed unknown access keyword to %s: %s') % (type(self).__name__, ' '.join(unknown_items)))

    @classmethod
    def _match(cls, raw_rule):
        return RE_PROFILE_USERNS.search(raw_rule)

    @classmethod
    def _create_instance(cls, raw_rule):
        '''parse raw_rule and return instance of this class'''

        matches = cls._match(raw_rule)
        if not matches:
            raise AppArmorException(_("Invalid userns rule '%s'") % raw_rule)

        audit, deny, allow_keyword, comment = parse_modifiers(matches)

        rule_details = ''
        if matches.group('details'):
            rule_details = matches.group('details')

        if rule_details:
            details = RE_USERNS_DETAILS.search(rule_details)
            if not details:
                raise AppArmorException(_("Invalid or unknown keywords in 'userns %s" % rule_details))

            access = details.group('access')
        else:
            access = cls.ALL

        return cls(access, audit=audit, deny=deny,
                   allow_keyword=allow_keyword, comment=comment)

    def get_clean(self, depth=0):
        '''return rule (in clean/default formatting)'''

        space = '  ' * depth

        if self.all_access:
            access = ''
        elif self.access:
            access = ' %s' % ' '.join(self.access)
        else:
            raise AppArmorBug('Empty access in userns rule')

        return('%s%suserns%s,%s' % (space, self.modifiers_str(), access, self.comment))

    def is_covered_localvars(self, other_rule):
        '''check if other_rule is covered by this rule object'''

        if not self._is_covered_list(self.access, self.all_access, other_rule.access, other_rule.all_access, 'access'):
            return False

        # still here? -> then it is covered
        return True

    def is_equal_localvars(self, rule_obj, strict):
        '''compare if rule-specific variables are equal'''

        if type(rule_obj) is not type(self):
            raise AppArmorBug('Passed non-userns rule: %s' % str(rule_obj))

        if (self.access != rule_obj.access or
                self.all_access != rule_obj.all_access):
            return False

        return True

    def logprof_header_localvars(self):
        access = logprof_value_or_all(self.access, self.all_access)

        return (
            _('Access mode'), access,
        )


class UserNamespaceRuleset(BaseRuleset):
    '''Class to handle and store a collection of userns rules'''

    def get_glob(self, path_or_rule):
        '''Return the next possible glob. For userns rules, that means removing access'''
        return 'userns,'
