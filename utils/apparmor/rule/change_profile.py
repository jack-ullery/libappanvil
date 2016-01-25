# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#    Copyright (C) 2015 Christian Boltz <apparmor@cboltz.de>
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

from apparmor.regex import RE_PROFILE_CHANGE_PROFILE, strip_quotes
from apparmor.common import AppArmorBug, AppArmorException, type_is_str
from apparmor.rule import BaseRule, BaseRuleset, parse_modifiers, quote_if_needed

# setup module translations
from apparmor.translations import init_translation
_ = init_translation()


class ChangeProfileRule(BaseRule):
    '''Class to handle and store a single change_profile rule'''

    # Nothing external should reference this class, all external users
    # should reference the class field ChangeProfileRule.ALL
    class __ChangeProfileAll(object):
        pass

    ALL = __ChangeProfileAll

    def __init__(self, execcond, targetprofile, audit=False, deny=False, allow_keyword=False,
                 comment='', log_event=None):

        '''
            CHANGE_PROFILE RULE = 'change_profile' [ EXEC COND ] [ -> PROGRAMCHILD ]
        '''

        super(ChangeProfileRule, self).__init__(audit=audit, deny=deny,
                                             allow_keyword=allow_keyword,
                                             comment=comment,
                                             log_event=log_event)

        self.execcond = None
        self.all_execconds = False
        if execcond == ChangeProfileRule.ALL:
            self.all_execconds = True
        elif type_is_str(execcond):
            if not execcond.strip():
                raise AppArmorBug('Empty exec condition in change_profile rule')
            elif execcond.startswith('/') or execcond.startswith('@'):
                self.execcond = execcond
            else:
                raise AppArmorException('Exec condition in change_profile rule does not start with /: %s' % str(execcond))
        else:
            raise AppArmorBug('Passed unknown object to ChangeProfileRule: %s' % str(execcond))

        self.targetprofile = None
        self.all_targetprofiles = False
        if targetprofile == ChangeProfileRule.ALL:
            self.all_targetprofiles = True
        elif type_is_str(targetprofile):
            if targetprofile.strip():
                self.targetprofile = targetprofile
            else:
                raise AppArmorBug('Empty target profile in change_profile rule')
        else:
            raise AppArmorBug('Passed unknown object to ChangeProfileRule: %s' % str(targetprofile))

    @classmethod
    def _match(cls, raw_rule):
        return RE_PROFILE_CHANGE_PROFILE.search(raw_rule)

    @classmethod
    def _parse(cls, raw_rule):
        '''parse raw_rule and return ChangeProfileRule'''

        matches = cls._match(raw_rule)
        if not matches:
            raise AppArmorException(_("Invalid change_profile rule '%s'") % raw_rule)

        audit, deny, allow_keyword, comment = parse_modifiers(matches)

        if matches.group('execcond'):
            execcond = strip_quotes(matches.group('execcond'))
        else:
            execcond = ChangeProfileRule.ALL

        if matches.group('targetprofile'):
            targetprofile = strip_quotes(matches.group('targetprofile'))
        else:
            targetprofile = ChangeProfileRule.ALL

        return ChangeProfileRule(execcond, targetprofile,
                           audit=audit, deny=deny, allow_keyword=allow_keyword, comment=comment)

    def get_clean(self, depth=0):
        '''return rule (in clean/default formatting)'''

        space = '  ' * depth

        if self.all_execconds:
            execcond = ''
        elif self.execcond:
            execcond = ' %s' % quote_if_needed(self.execcond)
        else:
            raise AppArmorBug('Empty execcond in change_profile rule')

        if self.all_targetprofiles:
            targetprofile = ''
        elif self.targetprofile:
            targetprofile = ' -> %s' % quote_if_needed(self.targetprofile)
        else:
            raise AppArmorBug('Empty target profile in change_profile rule')

        return('%s%schange_profile%s%s,%s' % (space, self.modifiers_str(), execcond, targetprofile, self.comment))

    def is_covered_localvars(self, other_rule):
        '''check if other_rule is covered by this rule object'''

        if not other_rule.execcond and not other_rule.all_execconds:
            raise AppArmorBug('No execcond specified in other change_profile rule')

        if not other_rule.targetprofile and not other_rule.all_targetprofiles:
            raise AppArmorBug('No target profile specified in other change_profile rule')

        if not self.all_execconds:
            if other_rule.all_execconds:
                return False
            if other_rule.execcond != self.execcond:
                # TODO: honor globbing and variables
                return False

        if not self.all_targetprofiles:
            if other_rule.all_targetprofiles:
                return False
            if other_rule.targetprofile != self.targetprofile:
                return False

        # still here? -> then it is covered
        return True

    def is_equal_localvars(self, rule_obj):
        '''compare if rule-specific variables are equal'''

        if not type(rule_obj) == ChangeProfileRule:
            raise AppArmorBug('Passed non-change_profile rule: %s' % str(rule_obj))

        if (self.execcond != rule_obj.execcond
                or self.all_execconds != rule_obj.all_execconds):
            return False

        if (self.targetprofile != rule_obj.targetprofile
                or self.all_targetprofiles != rule_obj.all_targetprofiles):
            return False

        return True

    def logprof_header_localvars(self):
        if self.all_execconds:
            execcond_txt = _('ALL')
        else:
            execcond_txt = self.execcond

        if self.all_targetprofiles:
            targetprofiles_txt = _('ALL')
        else:
            targetprofiles_txt = self.targetprofile

        return [
            _('Exec Condition'), execcond_txt,
            _('Target Profile'), targetprofiles_txt,
        ]

class ChangeProfileRuleset(BaseRuleset):
    '''Class to handle and store a collection of change_profile rules'''

    def get_glob(self, path_or_rule):
        '''Return the next possible glob. For change_profile rules, that can be "change_profile EXECCOND,",
           "change_profile -> TARGET_PROFILE," or "change_profile," (all change_profile).
           Also, EXECCOND filename can be globbed'''
        # XXX implement all options mentioned above ;-)
        return 'change_profile,'
