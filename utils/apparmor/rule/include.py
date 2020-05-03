# ----------------------------------------------------------------------
#    Copyright (C) 2020 Christian Boltz <apparmor@cboltz.de>
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

from apparmor.regex import RE_INCLUDE, re_match_include_parse
from apparmor.common import AppArmorBug, AppArmorException, type_is_str
from apparmor.rule import BaseRule, BaseRuleset, parse_comment

# setup module translations
from apparmor.translations import init_translation
_ = init_translation()


class IncludeRule(BaseRule):
    '''Class to handle and store a single include rule'''

    rule_name = 'include'

    def __init__(self, path, ifexists, ismagic, audit=False, deny=False, allow_keyword=False,
                 comment='', log_event=None):

        super(IncludeRule, self).__init__(audit=audit, deny=deny,
                                             allow_keyword=allow_keyword,
                                             comment=comment,
                                             log_event=log_event)

        # include doesn't support audit or deny
        if audit:
            raise AppArmorBug('Attempt to initialize IncludeRule with audit flag')
        if deny:
            raise AppArmorBug('Attempt to initialize IncludeRule with deny flag')

        if type(ifexists) is not bool:
            raise AppArmorBug('Passed unknown type for ifexists to IncludeRule: %s' % ifexists)
        if type(ismagic) is not bool:
            raise AppArmorBug('Passed unknown type for ismagic to IncludeRule: %s' % ismagic)
        if not type_is_str(path):
            raise AppArmorBug('Passed unknown type for path to IncludeRule: %s' % path)
        if not path:
            raise AppArmorBug('Passed empty path to IncludeRule: %s' % path)

        self.path = path
        self.ifexists = ifexists
        self.ismagic = ismagic

    @classmethod
    def _match(cls, raw_rule):
        return RE_INCLUDE.search(raw_rule)

    @classmethod
    def _parse(cls, raw_rule):
        '''parse raw_rule and return IncludeRule'''

        matches = cls._match(raw_rule)
        if not matches:
            raise AppArmorException(_("Invalid include rule '%s'") % raw_rule)

        comment = parse_comment(matches)

        # TODO: move re_match_include_parse() from regex.py to this class after converting all code to use IncludeRule
        path, ifexists, ismagic = re_match_include_parse(raw_rule)

        return IncludeRule(path, ifexists, ismagic,
                           audit=False, deny=False, allow_keyword=False, comment=comment)

    def get_clean(self, depth=0):
        '''return rule (in clean/default formatting)'''

        space = '  ' * depth

        ifexists_txt = ''
        if self.ifexists:
            ifexists_txt = ' if exists'

        if self.ismagic:
            return('%sinclude%s <%s>%s' % (space, ifexists_txt, self.path, self.comment))
        else:
            return('%sinclude%s "%s"%s' % (space, ifexists_txt, self.path, self.comment))

    def is_covered_localvars(self, other_rule):
        '''check if other_rule is covered by this rule object'''

        if (self.path != other_rule.path):
            return False

        if (self.ifexists != other_rule.ifexists) and (self.ifexists == True):  # "if exists" is allowed to differ
            return False

        if (self.ismagic != other_rule.ismagic):
            return False

        # still here? -> then it is covered
        return True

    def is_equal_localvars(self, rule_obj, strict):
        '''compare if rule-specific variables are equal'''

        if not type(rule_obj) == IncludeRule:
            raise AppArmorBug('Passed non-include rule: %s' % str(rule_obj))

        if (self.path != rule_obj.path):
            return False

        if (self.ifexists != rule_obj.ifexists):
            return False

        if (self.ismagic != rule_obj.ismagic):
            return False

        return True

    def logprof_header_localvars(self):
        return [
            _('Include'), self.get_clean(),
        ]


class IncludeRuleset(BaseRuleset):
    '''Class to handle and store a collection of include rules'''
    pass
