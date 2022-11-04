#!/usr/bin/python3
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

import unittest
from collections import namedtuple
from common_test import AATest, setup_all_loops

from apparmor.rule.userns import UserNamespaceRule, UserNamespaceRuleset
from apparmor.common import AppArmorException, AppArmorBug
from apparmor.translations import init_translation
_ = init_translation()


class UserNamespaceTestParse(AATest):
    tests = (
        #                                          access                 audit  deny   allow  comment
        ('userns,',              UserNamespaceRule(UserNamespaceRule.ALL, False, False, False, '')),
        ('userns create,',       UserNamespaceRule(('create'),            False, False, False, '')),
        ('audit userns create,', UserNamespaceRule(('create'),            True,  False, False, '')),
        ('deny userns,',         UserNamespaceRule(UserNamespaceRule.ALL, False, True,  False, '')),
        ('audit allow userns,',  UserNamespaceRule(UserNamespaceRule.ALL, True,  False, True,  '')),
        ('userns create, # cmt', UserNamespaceRule(('create'),            False, False, False, ' # cmt')),
        )

    def _run_test(self, rawrule, expected):
        self.assertTrue(UserNamespaceRule.match(rawrule))
        obj = UserNamespaceRule.create_instance(rawrule)
        expected.raw_rule = rawrule.strip()
        self.assertTrue(obj.is_equal(expected, True))


class UserNamespaceTestParseInvalid(AATest):
    tests = (
        ('userns invalidaccess,', AppArmorException),
    )

    def _run_test(self, rawrule, expected):
        self.assertTrue(UserNamespaceRule.match(rawrule))  # the above invalid rules still match the main regex!
        with self.assertRaises(expected):
            UserNamespaceRule.create_instance(rawrule)

    def test_parse_fail(self):
        with self.assertRaises(AppArmorException):
            UserNamespaceRule.create_instance('foo,')

    def test_diff_non_usernsrule(self):
        exp = namedtuple('exp', ('audit', 'deny'))
        obj = UserNamespaceRule(('create'))
        with self.assertRaises(AppArmorBug):
            obj.is_equal(exp(False, False), False)

    def test_diff_access(self):
        obj1 = UserNamespaceRule(UserNamespaceRule.ALL)
        obj2 = UserNamespaceRule(('create'))
        self.assertFalse(obj1.is_equal(obj2, False))


class InvalidUserNamespaceInit(AATest):
    tests = (
        # init params  expected exception
        ((''),         TypeError),          # empty access
        (('    '),     AppArmorBug),        # whitespace access
        (('xyxy'),     AppArmorException),  # invalid access
        (dict(),       TypeError),          # wrong type for access
        (None,         TypeError),          # wrong type for access
    )

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            UserNamespaceRule(*params)

    def test_missing_params(self):
        with self.assertRaises(TypeError):
            UserNamespaceRule()

class WriteUserNamespaceTestAATest(AATest):
    tests = (
        #  raw rule                              clean rule
        ('     userns         ,    # foo    ',   'userns, # foo'),
        ('    audit     userns create,',         'audit userns create,'),
        ('   deny userns      ,# foo bar',       'deny userns, # foo bar'),
        ('   allow userns  create   ,# foo bar', 'allow userns create, # foo bar'),
        ('userns,',                              'userns,'),
        ('userns create,',                       'userns create,'),
    )

    def _run_test(self, rawrule, expected):
        self.assertTrue(UserNamespaceRule.match(rawrule))
        obj = UserNamespaceRule.create_instance(rawrule)
        clean = obj.get_clean()
        raw = obj.get_raw()

        self.assertEqual(expected.strip(), clean, 'unexpected clean rule')
        self.assertEqual(rawrule.strip(), raw, 'unexpected raw rule')

    def test_write_manually(self):
        obj = UserNamespaceRule('create', allow_keyword=True)

        expected = '    allow userns create,'

        self.assertEqual(expected, obj.get_clean(2), 'unexpected clean rule')
        self.assertEqual(expected, obj.get_raw(2), 'unexpected raw rule')

    def test_write_invalid_access(self):
        obj = UserNamespaceRule('create')
        obj.access = ''
        with self.assertRaises(AppArmorBug):
            obj.get_clean()


class UserNamespaceIsCoveredTest(AATest):
    def test_is_covered(self):
        obj = UserNamespaceRule(UserNamespaceRule.ALL)
        self.assertTrue(obj.is_covered(UserNamespaceRule(('create'))))
        self.assertTrue(obj.is_covered(UserNamespaceRule(UserNamespaceRule.ALL)))

    def test_is_not_covered(self):
        obj = UserNamespaceRule(('create'))
        self.assertFalse(obj.is_covered(UserNamespaceRule(UserNamespaceRule.ALL)))


class UserNamespaceLogprofHeaderTest(AATest):
    tests = (
        ('userns,',        [_('Access mode'), _('ALL')]),
        ('userns create,', [_('Access mode'), 'create']),
    )

    def _run_test(self, params, expected):
        obj = UserNamespaceRule.create_instance(params)
        self.assertEqual(obj.logprof_header(), expected)


class UserNamespaceGlobTestAATest(AATest):
    def test_glob(self):
        self.assertEqual(UserNamespaceRuleset().get_glob('userns create,'), 'userns,')


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
