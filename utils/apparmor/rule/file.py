# ----------------------------------------------------------------------
#    Copyright (C) 2016 Christian Boltz <apparmor@cboltz.de>
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

from apparmor.regex import RE_PROFILE_FILE_ENTRY, strip_quotes
from apparmor.common import AppArmorBug, AppArmorException, type_is_str
from apparmor.rule import BaseRule, BaseRuleset, check_and_split_list, logprof_value_or_all, parse_modifiers, quote_if_needed

# setup module translations
from apparmor.translations import init_translation
_ = init_translation()


allow_exec_transitions          = ('ix', 'ux', 'Ux', 'px', 'Px', 'cx', 'Cx')  # 2 chars - len relevant for split_perms()
allow_exec_fallback_transitions = ('pix', 'Pix', 'cix', 'Cix', 'pux', 'PUx', 'cux', 'CUx')  # 3 chars - len relevant for split_perms()
deny_exec_transitions           = ('x')
file_permissions                = ('m', 'r', 'w', 'a', 'l', 'k')  # also defines the write order



class FileRule(BaseRule):
    '''Class to handle and store a single file rule'''

    # Nothing external should reference this class, all external users
    # should reference the class field FileRule.ALL
    class __FileAll(object):
        pass

    ALL = __FileAll

    rule_name = 'file'

    def __init__(self, path, perms, exec_perms, target, owner, file_keyword=False, leading_perms=False,
                audit=False, deny=False, allow_keyword=False, comment='', log_event=None):
        '''Initialize FileRule

           Parameters:
           - path: string, AARE or FileRule.ALL
           - perms: string, set of chars or FileRule.ALL (must not contain exec mode)
           - exec_perms: None or string
           - target: string, AARE or FileRule.ALL
           - owner: bool
           - file_keyword: bool
           - leading_perms: bool
        '''

        super(FileRule, self).__init__(audit=audit, deny=deny, allow_keyword=allow_keyword,
                                             comment=comment, log_event=log_event)

        #                                                               rulepart        partperms       is_path log_event
        self.path,          self.all_paths          = self._aare_or_all(path,           'path',         True,   log_event)
        self.target,        self.all_targets,       = self._aare_or_all(target,         'target',       False,  log_event)

        if type_is_str(perms):
            perms, tmp_exec_perms = split_perms(perms, deny)
            if tmp_exec_perms:
                raise AppArmorBug('perms must not contain exec perms')
        elif perms == None:
            perms = set()

        self.perms, self.all_perms, unknown_items = check_and_split_list(perms, file_permissions, FileRule.ALL, 'FileRule', 'permissions', allow_empty_list=True)
        if unknown_items:
            raise AppArmorBug('Passed unknown perms to FileRule: %s' % str(unknown_items))
        if self.perms and 'a' in self.perms and 'w' in self.perms:
            raise AppArmorException("Conflicting permissions found: 'a' and 'w'")

        if exec_perms is None:
            self.exec_perms = None
        elif type_is_str(exec_perms):
            if deny:
                if exec_perms != 'x':
                    raise AppArmorException(_("file deny rules only allow to use 'x' as execute mode, but not %s" % exec_perms))
            else:
                if exec_perms == 'x':
                    raise AppArmorException(_("Execute flag ('x') in file rule must specify the exec mode (ix, Px, Cx etc.)"))
                elif exec_perms not in allow_exec_transitions and exec_perms not in allow_exec_fallback_transitions:
                    raise AppArmorBug('Unknown execute mode specified in file rule: %s' % exec_perms)
            self.exec_perms = exec_perms
        else:
            raise AppArmorBug('Passed unknown perms object to FileRule: %s' % str(perms))

        if type(owner) is not bool:
            raise AppArmorBug('non-boolean value passed to owner flag')
        self.owner = owner

        if type(file_keyword) is not bool:
            raise AppArmorBug('non-boolean value passed to file keyword flag')
        self.file_keyword = file_keyword

        if type(leading_perms) is not bool:
            raise AppArmorBug('non-boolean value passed to leading permissions flag')
        self.leading_perms = leading_perms

        # XXX subset

        # check for invalid combinations (bare 'file,' vs. path rule)
#       if (self.all_paths and not self.all_perms) or (not self.all_paths and self.all_perms):
#           raise AppArmorBug('all_paths and all_perms must be equal')
# elif
        if self.all_paths and (self.exec_perms or self.target):
            raise AppArmorBug('exec perms or target specified for bare file rule')

    @classmethod
    def _match(cls, raw_rule):
        return RE_PROFILE_FILE_ENTRY.search(raw_rule)

    @classmethod
    def _parse(cls, raw_rule):
        '''parse raw_rule and return FileRule'''

        matches = cls._match(raw_rule)
        if not matches:
            raise AppArmorException(_("Invalid file rule '%s'") % raw_rule)

        audit, deny, allow_keyword, comment = parse_modifiers(matches)

        owner = bool(matches.group('owner'))

        leading_perms = False

        if matches.group('path'):
            path = strip_quotes(matches.group('path'))
        elif matches.group('path2'):
            path = strip_quotes(matches.group('path2'))
            leading_perms = True
        else:
            path = FileRule.ALL

        if matches.group('perms'):
            perms = matches.group('perms')
            perms, exec_perms = split_perms(perms, deny)
        elif matches.group('perms2'):
            perms = matches.group('perms2')
            perms, exec_perms = split_perms(perms, deny)
            leading_perms = True
        else:
            perms = FileRule.ALL
            exec_perms = None

        if matches.group('target'):
            target = strip_quotes(matches.group('target'))
        else:
            target = FileRule.ALL

        file_keyword = bool(matches.group('file_keyword'))

        return FileRule(path, perms, exec_perms, target, owner, file_keyword, leading_perms,
                           audit=audit, deny=deny, allow_keyword=allow_keyword, comment=comment)

    def get_clean(self, depth=0):
        '''return rule (in clean/default formatting)'''

        space = '  ' * depth

        if self.all_paths:
            path = ''
        elif self.path:
            path = quote_if_needed(self.path.regex)
        else:
            raise AppArmorBug('Empty path in file rule')

        if self.all_perms:
            perms = ''
        else:
            perms = self._joint_perms()
            if not perms:
                raise AppArmorBug('Empty permissions in file rule')

        if self.leading_perms:
            path_and_perms = '%s %s' % (perms, path)
        else:
            path_and_perms = '%s %s' % (path, perms)

        if self.all_targets:
            target = ''
        elif self.target:
            target = ' -> %s' % quote_if_needed(self.target.regex)
        else:
            raise AppArmorBug('Empty exec target in file rule')

        if self.owner:
            owner = 'owner '
        else:
            owner = ''

        if self.file_keyword:
            file_keyword = 'file '
        else:
            file_keyword = ''

        if self.all_paths and self.all_perms and not path and not perms and not target:
            return('%s%s%sfile,%s' % (space, self.modifiers_str(), owner, self.comment))  # plain 'file,' rule
        elif not self.all_paths and not self.all_perms and path and perms:
            return('%s%s%s%s%s%s,%s' % (space, self.modifiers_str(), file_keyword, owner, path_and_perms, target, self.comment))
        else:
            raise AppArmorBug('Invalid combination of path and perms in file rule - either specify path and perms, or none of them')

    def _joint_perms(self):
        '''return the permissions as string'''
        perm_string = ''
        for perm in file_permissions:
            if perm in self.perms:
                perm_string = perm_string + perm

        if self.exec_perms:
            perm_string = perm_string + self.exec_perms

        return perm_string

    def is_covered_localvars(self, other_rule):
        '''check if other_rule is covered by this rule object'''

        if not self._is_covered_aare(self.path,         self.all_paths,         other_rule.path,        other_rule.all_paths,           'path'):
            return False

        # TODO: check 'a' vs. 'w'
        # perms can be empty if only exec_perms are specified, therefore disable the sanity check in _is_covered_list()...
        if not self._is_covered_list(self.perms,        self.all_perms,         other_rule.perms,       other_rule.all_perms,           'perms', sanity_check=False):
            return False

        # ... and do our own sanity check
        if not other_rule.perms and not other_rule.all_perms and not other_rule.exec_perms:
            raise AppArmorBug('No permission or exec permission specified in other file rule')

        if not self.exec_perms and other_rule.exec_perms:
            return False

        # TODO: handle fallback modes?
        if other_rule.exec_perms and self.exec_perms != other_rule.exec_perms:
            return False

        # check exec_mode and target only if other_rule contains exec_perms or link permissions
        # (for mrwk permissions, the target is ignored anyway)
        if other_rule.exec_perms or (other_rule.perms and 'l' in other_rule.perms):
            if not self._is_covered_aare(self.target,   self.all_targets,       other_rule.target,      other_rule.all_targets,         'target'):
                return False

            # a different target means running with a different profile, therefore we have to be more strict than _is_covered_aare()
            # XXX should we enforce an exact match for a) exec and/or b) link target?
            if self.all_targets != other_rule.all_targets:
                return False

        if self.owner and not other_rule.owner:
            return False

        # no check for file_keyword and leading_perms - they are not relevant for is_covered()

        # still here? -> then it is covered
        return True


    def is_equal_localvars(self, rule_obj, strict):
        '''compare if rule-specific variables are equal'''

        if not type(rule_obj) == FileRule:
            raise AppArmorBug('Passed non-file rule: %s' % str(rule_obj))

        if self.owner != rule_obj.owner:
            return False

        if not self._is_equal_aare(self.path,           self.all_paths,         rule_obj.path,          rule_obj.all_paths,             'path'):
            return False

        if self.perms != rule_obj.perms:
            return False

        if self.all_perms != rule_obj.all_perms:
            return False

        if self.exec_perms != rule_obj.exec_perms:
            return False

        if not self._is_equal_aare(self.target,         self.all_targets,       rule_obj.target,        rule_obj.all_targets,           'target'):
            return False

        if strict:  # file_keyword and leading_perms are only cosmetics, but still a difference
            if self.file_keyword != rule_obj.file_keyword:
                return False

            if self.leading_perms != rule_obj.leading_perms:
                return False

        return True

    def logprof_header_localvars(self):
        if self.owner:
            owner = _('Yes')
        else:
            owner = _('No')

        path    = logprof_value_or_all(self.path,       self.all_paths)
        perms   = logprof_value_or_all(self.perms,      self.all_perms)
        if self.exec_perms:
            perms = perms + self.exec_perms
        target  = logprof_value_or_all(self.target,     self.all_targets)

        return [
            _('Owner only'),    owner,
            _('Path'),          path,
            _('Permissions'),   perms,
            _('Target'),        target,
            # file_keyword and leading_perms are not really relevant
        ]


class FileRuleset(BaseRuleset):
    '''Class to handle and store a collection of file rules'''

    def get_glob(self, path_or_rule):
        '''Return the next possible glob. For file rules, that means removing owner or globbing the path'''
        # XXX only remove one part, not all
        return 'file,'


def split_perms(perm_string, deny):
    '''parse permission string
       - perm_string: the permission string to parse
       - deny: True if this is a deny rule
   '''
    perms = set()
    exec_mode = None

    while perm_string:
        if perm_string[0] in file_permissions:
            perms.add(perm_string[0])
            perm_string = perm_string[1:]
        elif perm_string[0] == 'x':
            if not deny:
                raise AppArmorException(_("'x' must be preceded by an exec qualifier (i, P, C or U)"))
            exec_mode = 'x'
            perm_string = perm_string[1:]
        elif perm_string.startswith(allow_exec_transitions):
            if exec_mode and exec_mode != perm_string[0:2]:
                raise AppArmorException(_('conflicting execute permissions found: %s and %s' % (exec_mode, perm_string[0:2])))
            exec_mode = perm_string[0:2]
            perm_string = perm_string[2:]
        elif perm_string.startswith(allow_exec_fallback_transitions):
            if exec_mode and exec_mode != perm_string[0:3]:
                raise AppArmorException(_('conflicting execute permissions found: %s and %s' % (exec_mode, perm_string[0:3])))
            exec_mode = perm_string[0:3]
            perm_string = perm_string[3:]
        else:
            raise AppArmorException(_('permission contains unknown character(s) %s' % perm_string))

    return perms, exec_mode
