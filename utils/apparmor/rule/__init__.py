# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#    Copyright (C) 2014 Christian Boltz <apparmor@cboltz.de>
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

from apparmor.common import AppArmorBug

# setup module translations
from apparmor.translations import init_translation
_ = init_translation()


class BaseRule(object):
    '''Base class to handle and store a single rule'''

    def __init__(self, audit=False, deny=False, allow_keyword=False,
                 comment='', log_event=None, raw_rule=''):
        '''initialize variables needed by all rule types'''
        self.audit = audit
        self.deny = deny
        self.allow_keyword = allow_keyword

        self.comment = comment

        self.raw_rule = raw_rule.strip() if raw_rule else None
        self.log_event = log_event

    def get_raw(self, depth=0):
        '''return raw rule (with original formatting, and leading whitespace in the depth parameter)'''
        if self.raw_rule:
            return '%s%s' % ('  ' * depth, self.raw_rule)
        else:
            return self.get_clean(depth)

    def is_equal(self, rule_obj, strict=False):
        '''compare if rule_obj == self
           Calls is_equal_localvars() to compare rule-specific variables'''

        if self.audit != rule_obj.audit or self.deny != rule_obj.deny:
            return False

        if strict and (
            self.allow_keyword != rule_obj.allow_keyword
            or self.comment != rule_obj.comment
            or self.raw_rule != rule_obj.raw_rule
        ):
            return False

        return self.is_equal_localvars(rule_obj)

    def modifiers_str(self):
        '''return the allow/deny and audit keyword as string, including whitespace'''

        if self.audit:
            auditstr = 'audit '
        else:
            auditstr = ''

        if self.deny:
            allowstr = 'deny '
        elif self.allow_keyword:
            allowstr = 'allow '
        else:
            allowstr = ''

        return '%s%s' % (auditstr, allowstr)


class BaseRuleset(object):
    '''Base class to handle and store a collection of rules'''

    # decides if the (G)lob and Glob w/ (E)xt options are displayed
    can_glob = True
    can_glob_ext = False

    def __init__(self):
        '''initialize variables needed by all ruleset types
           Do not override in child class unless really needed - override _init_vars() instead'''
        self.rules = []
        self._init_vars()

    def _init_vars(self):
        '''called by __init__() and delete_all_rules() - override in child class to initialize more variables'''
        pass

    def add(self, rule):
        '''add a rule object'''
        self.rules.append(rule)

    def get_raw(self, depth=0):
        '''return all raw rules (if possible/not modified in their original formatting).
           Returns an array of lines, with depth * leading whitespace'''

        data = []
        for rule in self.rules:
            data.append(rule.get_raw(depth))

        if data:
            data.append('')

        return data

    def get_clean(self, depth=0):
        '''return all rules (in clean/default formatting)
           Returns an array of lines, with depth * leading whitespace'''

        allow_rules = []
        deny_rules = []

        for rule in self.rules:
            if rule.deny:
                deny_rules.append(rule.get_clean(depth))
            else:
                allow_rules.append(rule.get_clean(depth))

        allow_rules.sort()
        deny_rules.sort()

        cleandata = []

        if deny_rules:
            cleandata += deny_rules
            cleandata.append('')

        if allow_rules:
            cleandata += allow_rules
            cleandata.append('')

        return cleandata

    def is_covered(self, rule, check_allow_deny=True, check_audit=False):
        '''return True if rule is covered by existing rules, otherwise False'''

        for r in self.rules:
            if r.is_covered(rule, check_allow_deny, check_audit):
                return True

        return False

#    def is_log_covered(self, parsed_log_event, check_allow_deny=True, check_audit=False):
#        '''return True if parsed_log_event is covered by existing rules, otherwise False'''
#
#        rule_obj = self.new_rule()
#        rule_obj.set_log(parsed_log_event)
#
#        return self.is_covered(rule_obj, check_allow_deny, check_audit)

    def delete(self, rule):
        '''Delete rule from rules'''

        rule_to_delete = False
        i = 0
        for r in self.rules:
            if r.is_equal(rule):
                rule_to_delete = True
                break
            i = i + 1

        if rule_to_delete:
            self.rules.pop(i)
        else:
            raise AppArmorBug('Attempt to delete non-existing rule %s' % rule.get_raw(0))

    def delete_duplicates(self, include_rules):
        '''Delete duplicate rules.
           include_rules must be a *_rules object'''
        deleted = []
        if include_rules:  # avoid breakage until we have a proper function to ensure all profiles contain all *_rules objects
            for rule in self.rules:
                if include_rules.is_covered(rule, True, True):
                    self.delete(rule)
                    deleted.append(rule)

        return len(deleted)

    def get_glob_ext(self, path_or_rule):
        '''returns the next possible glob with extension (for file rules only).
           For all other rule types, raise an exception'''
        raise AppArmorBug("get_glob_ext is not available for this rule type!")


def parse_modifiers(matches):
    '''returns audit, deny, allow_keyword and comment from the matches object
       - audit, deny and allow_keyword are True/False
       - comment is the comment with a leading space'''
    audit = False
    if matches.group('audit'):
        audit = True

    deny = False
    allow_keyword = False

    allowstr = matches.group('allow')
    if allowstr:
        if allowstr.strip() == 'allow':
            allow_keyword = True
        elif allowstr.strip() == 'deny':
            deny = True
        else:
            raise AppArmorBug("Invalid allow/deny keyword %s" % allowstr)

    comment = ''
    if matches.group('comment'):
        # include a space so that we don't need to add it everywhere when writing the rule
        comment = ' %s' % matches.group('comment')

    return (audit, deny, allow_keyword, comment)
