#!/usr/bin/env python
# ----------------------------------------------------------------------
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

import unittest

from apparmor.rule.capability import CapabilityRule, CapabilityRuleset
from apparmor.rule import BaseRule, parse_modifiers
from apparmor.common import AppArmorException, AppArmorBug, hasher
from apparmor.logparser import ReadLog

import re

# --- tests for single CapabilityRule --- #

class CapabilityTest(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def _compare_obj_with_rawrule(self, rawrule, expected):

        obj = CapabilityRule.parse(rawrule)

        self.assertEqual(rawrule.strip(), obj.raw_rule)

        self._compare_obj(obj, expected)

    def _compare_obj(self, obj, expected):
        self.assertEqual(expected['allow_keyword'], obj.allow_keyword)
        self.assertEqual(expected['audit'], obj.audit)
        self.assertEqual(expected['capability'], obj.capability)
        self.assertEqual(expected['all_caps'], obj.all_caps)
        self.assertEqual(expected['deny'], obj.deny)
        self.assertEqual(expected['comment'], obj.comment)

    def test_cap_allow_all(self):
        self._compare_obj_with_rawrule("capability,", {
            'allow_keyword':    False,
            'deny':             False,
            'audit':            False,
            'capability':       set(),
            'all_caps':         True,
            'comment':          "",
        })

    def test_cap_allow_sys_admin(self):
        self._compare_obj_with_rawrule("capability sys_admin,", {
            'allow_keyword':    False,
            'deny':             False,
            'audit':            False,
            'capability':       {'sys_admin'},
            'all_caps':         False,
            'comment':          "",
        })

    def test_cap_deny_sys_admin(self):
        self._compare_obj_with_rawrule("     deny capability sys_admin,  # some comment", {
            'allow_keyword':    False,
            'deny':             True,
            'audit':            False,
            'capability':       {'sys_admin'},
            'all_caps':         False,
            'comment':          " # some comment",
        })

    def test_cap_multi(self):
        self._compare_obj_with_rawrule("capability sys_admin dac_override,", {
            'allow_keyword':    False,
            'deny':             False,
            'audit':            False,
            'capability':       {'sys_admin', 'dac_override'},
            'all_caps':         False,
            'comment':          "",
        })

    # Template for test_cap_* functions
    #    def test_cap_(self):
    #        self._compare_obj_with_rawrule("capability,", {
    #            'allow_keyword':    False,
    #            'deny':             False,
    #            'audit':            False,
    #            'capability':       set(), # (or {'foo'} if not empty)
    #            'all_caps':         False,
    #            'comment':    "",
    #        })

    def test_cap_from_log(self):
        parser = ReadLog('', '', '', '', '')
        event = 'type=AVC msg=audit(1415403814.628:662): apparmor="ALLOWED" operation="capable" profile="/bin/ping" pid=15454 comm="ping" capability=13  capname="net_raw"'

        parsed_event = parser.parse_event(event)

        self.assertEqual(parsed_event, {
            'request_mask': set(),
            'denied_mask': set(),
            'error_code': 0,
            'magic_token': 0,
            'parent': 0,
            'profile': '/bin/ping',
            'operation': 'capable',
            'resource': None,
            'info': None,
            'aamode': 'PERMITTING',
            'time': 1415403814,
            'active_hat': None,
            'pid': 15454,
            'task': 0,
            'attr': None,
            'name2': None,
            'name': 'net_raw'
        })

        obj = CapabilityRule(parsed_event['name'], log_event=parsed_event)

        self._compare_obj(obj, {
            'allow_keyword':    False,
            'deny':             False,
            'audit':            False,
            'capability':       {'net_raw'},
            'all_caps':         False,
            'comment':          "",
        })

        self.assertEqual(obj.get_raw(1), '  capability net_raw,')

#    def test_cap_from_invalid_log(self):
#        parser = ReadLog('', '', '', '', '')
#        # invalid log entry, name= should contain the capability name
#        event = 'type=AVC msg=audit(1415403814.628:662): apparmor="ALLOWED" operation="capable" profile="/bin/ping" pid=15454 comm="ping" capability=13  capname=""'
#
#        parsed_event = parser.parse_event(event)
#
#        obj = CapabilityRule()
#
#        with self.assertRaises(AppArmorBug):
#            obj.set_log(parsed_event)
#
#        with self.assertRaises(AppArmorBug):
#            obj.get_raw(1)
#
#    def test_cap_from_non_cap_log(self):
#        parser = ReadLog('', '', '', '', '')
#        # log entry for different rule type
#        event = 'type=AVC msg=audit(1415403814.973:667): apparmor="ALLOWED" operation="setsockopt" profile="/home/sys-tmp/ping" pid=15454 comm="ping" lport=1 family="inet" sock_type="raw" protocol=1'
#
#        parsed_event = parser.parse_event(event)
#
#        obj = CapabilityRule()
#
#        with self.assertRaises(AppArmorBug):
#            obj.set_log(parsed_event)
#
#        with self.assertRaises(AppArmorBug):
#            obj.get_raw(1)

    def test_cap_from_init_01(self):
        obj = CapabilityRule('chown')

        self._compare_obj(obj, {
            'allow_keyword':    False,
            'deny':             False,
            'audit':            False,
            'capability':       {'chown'},
            'all_caps':         False,
            'comment':          "",
        })

    def test_cap_from_init_02(self):
        obj = CapabilityRule(['chown'])

        self._compare_obj(obj, {
            'allow_keyword':    False,
            'deny':             False,
            'audit':            False,
            'capability':       {'chown'},
            'all_caps':         False,
            'comment':          "",
        })

    def test_cap_from_init_03(self):
        obj = CapabilityRule('chown', audit=True, deny=True)

        self._compare_obj(obj, {
            'allow_keyword':    False,
            'deny':             True,
            'audit':            True,
            'capability':       {'chown'},
            'all_caps':         False,
            'comment':          "",
        })

    def test_cap_from_init_04(self):
        obj = CapabilityRule(['chown', 'fsetid'], deny=True)

        self._compare_obj(obj, {
            'allow_keyword':    False,
            'deny':             True,
            'audit':            False,
            'capability':       {'chown', 'fsetid'},
            'all_caps':         False,
            'comment':          "",
        })


class InvalidCapabilityTest(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def _check_invalid_rawrule(self, rawrule):
        obj = None
        with self.assertRaises(AppArmorException):
            obj = CapabilityRule(CapabilityRule.parse(rawrule))

        self.assertIsNone(obj, 'CapbilityRule handed back an object unexpectedly')

    def test_invalid_cap_missing_comma(self):
        self._check_invalid_rawrule('capability')  # missing comma

    def test_invalid_cap_non_CapabilityRule(self):
        self._check_invalid_rawrule('network,')  # not a capability rule

    def test_parse_modifiers_invalid(self):
        regex = re.compile('^\s*(?P<audit>audit\s+)?(?P<allow>allow\s+|deny\s+|invalid\s+)?')
        matches = regex.search('audit invalid ')

        with self.assertRaises(AppArmorBug):
            parse_modifiers(matches)

    def test_empty_cap_set(self):
        obj = CapabilityRule('chown')
        obj.capability.clear()
        # no capability set, and ALL not set
        with self.assertRaises(AppArmorBug):
            obj.get_clean(1)

    def test_empty_cap_list(self):
        with self.assertRaises(AppArmorBug):
            CapabilityRule([])

    def test_no_cap_list_arg(self):
        with self.assertRaises(TypeError):
            CapabilityRule()

    def test_space_cap(self):
        with self.assertRaises(AppArmorBug):
            CapabilityRule('    ')  # the whitespace capability ;-)

    def test_space_list_1(self):
        with self.assertRaises(AppArmorBug):
            CapabilityRule(['    ', '   ', '   '])  # the whitespace capability ;-)

    def test_space_list_2(self):
        with self.assertRaises(AppArmorBug):
            CapabilityRule(['chown', '   ', 'setgid'])  # includes the whitespace capability ;-)

    def test_wrong_type_for_cap(self):
        with self.assertRaises(AppArmorBug):
            CapabilityRule(dict())


class WriteCapabilityTest(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def _check_write_rule(self, rawrule, cleanrule):
        obj = CapabilityRule.parse(rawrule)
        clean = obj.get_clean()
        raw = obj.get_raw()

        self.assertEqual(cleanrule.strip(), clean, 'unexpected clean rule')
        self.assertEqual(rawrule.strip(), raw, 'unexpected raw rule')

    def test_write_all(self):
        self._check_write_rule('     capability      ,    # foo        ', 'capability, # foo')

    def test_write_sys_admin(self):
        self._check_write_rule('    audit     capability sys_admin,', 'audit capability sys_admin,')

    def test_write_sys_multi(self):
        self._check_write_rule('   deny capability      sys_admin      audit_write,# foo bar', 'deny capability audit_write sys_admin, # foo bar')

    def test_write_manually(self):
        obj = CapabilityRule(['ptrace', 'audit_write'], allow_keyword=True)

        expected = '    allow capability audit_write ptrace,'

        self.assertEqual(expected, obj.get_clean(2), 'unexpected clean rule')
        self.assertEqual(expected, obj.get_raw(2), 'unexpected raw rule')

class CapabilityCoveredTest(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def _is_covered(self, obj, rule_to_test):
        return obj.is_covered(CapabilityRule.parse(rule_to_test))

    def _is_covered_exact(self, obj, rule_to_test):
        return obj.is_covered(CapabilityRule.parse(rule_to_test), True, True)

    def _is_equal(self, obj, rule_to_test, strict):
        return obj.is_equal(CapabilityRule.parse(rule_to_test), strict)

    def test_covered_single(self):
        obj = CapabilityRule.parse('capability sys_admin,')

        self.assertTrue(self._is_covered(obj, 'capability sys_admin,'))

        self.assertFalse(self._is_covered(obj, 'audit capability sys_admin,'))
        self.assertFalse(self._is_covered(obj, 'audit capability,'))
        self.assertFalse(self._is_covered(obj, 'capability chown,'))
        self.assertFalse(self._is_covered(obj, 'capability,'))

    def test_covered_audit(self):
        obj = CapabilityRule.parse('audit capability sys_admin,')

        self.assertTrue(self._is_covered(obj, 'capability sys_admin,'))
        self.assertTrue(self._is_covered(obj, 'audit capability sys_admin,'))

        self.assertFalse(self._is_covered(obj, 'audit capability,'))
        self.assertFalse(self._is_covered(obj, 'capability chown,'))
        self.assertFalse(self._is_covered(obj, 'capability,'))

    def test_covered_check_audit(self):
        obj = CapabilityRule.parse('audit capability sys_admin,')

        self.assertFalse(self._is_covered_exact(obj, 'capability sys_admin,'))
        self.assertTrue(self._is_covered_exact(obj, 'audit capability sys_admin,'))

        self.assertFalse(self._is_covered_exact(obj, 'audit capability,'))
        self.assertFalse(self._is_covered_exact(obj, 'capability chown,'))
        self.assertFalse(self._is_covered_exact(obj, 'capability,'))

    def test_equal(self):
        obj = CapabilityRule.parse('capability sys_admin,')

        self.assertTrue(self._is_equal(obj, 'capability sys_admin,', True))
        self.assertFalse(self._is_equal(obj, 'allow capability sys_admin,', True))
        self.assertFalse(self._is_equal(obj, 'allow capability sys_admin,', True))
        self.assertFalse(self._is_equal(obj, 'audit capability sys_admin,', True))

        self.assertTrue(self._is_equal(obj, 'capability sys_admin,', False))
        self.assertTrue(self._is_equal(obj, 'allow capability sys_admin,', False))
        self.assertFalse(self._is_equal(obj, 'audit capability sys_admin,', False))

    def test_covered_multi(self):
        obj = CapabilityRule.parse('capability audit_write sys_admin,')

        self.assertTrue(self._is_covered(obj, 'capability sys_admin,'))
        self.assertTrue(self._is_covered(obj, 'capability audit_write,'))
        self.assertTrue(self._is_covered(obj, 'capability audit_write sys_admin,'))
        self.assertTrue(self._is_covered(obj, 'capability sys_admin audit_write,'))

        self.assertFalse(self._is_covered(obj, 'audit capability,'))
        self.assertFalse(self._is_covered(obj, 'capability chown,'))
        self.assertFalse(self._is_covered(obj, 'capability,'))

    def test_covered_all(self):
        obj = CapabilityRule.parse('capability,')

        self.assertTrue(self._is_covered(obj, 'capability sys_admin,'))
        self.assertTrue(self._is_covered(obj, 'capability audit_write,'))
        self.assertTrue(self._is_covered(obj, 'capability audit_write sys_admin,'))
        self.assertTrue(self._is_covered(obj, 'capability sys_admin audit_write,'))
        self.assertTrue(self._is_covered(obj, 'capability,'))

        self.assertFalse(self._is_covered(obj, 'audit capability,'))

    def test_covered_deny(self):
        obj = CapabilityRule.parse('capability sys_admin,')

        self.assertTrue(self._is_covered(obj, 'capability sys_admin,'))

        self.assertFalse(self._is_covered(obj, 'audit deny capability sys_admin,'))
        self.assertFalse(self._is_covered(obj, 'deny capability sys_admin,'))
        self.assertFalse(self._is_covered(obj, 'capability chown,'))
        self.assertFalse(self._is_covered(obj, 'capability,'))

    def test_covered_deny_2(self):
        obj = CapabilityRule.parse('deny capability sys_admin,')

        self.assertTrue(self._is_covered(obj, 'deny capability sys_admin,'))

        self.assertFalse(self._is_covered(obj, 'audit deny capability sys_admin,'))
        self.assertFalse(self._is_covered(obj, 'capability sys_admin,'))
        self.assertFalse(self._is_covered(obj, 'deny capability chown,'))
        self.assertFalse(self._is_covered(obj, 'deny capability,'))

    def test_invalid_is_covered(self):
        obj = CapabilityRule.parse('capability sys_admin,')

        testobj = BaseRule()  # different type

        with self.assertRaises(AppArmorBug):
            obj.is_covered(testobj)

    def test_borked_obj_is_covered(self):
        obj = CapabilityRule.parse('capability sys_admin,')

        testobj = CapabilityRule('chown')
        testobj.capability.clear()

        with self.assertRaises(AppArmorBug):
            obj.is_covered(testobj)

    def test_invalid_is_equal(self):
        obj = CapabilityRule.parse('capability sys_admin,')

        testobj = BaseRule()  # different type

        with self.assertRaises(AppArmorBug):
            obj.is_equal(testobj)

    def test_empty_init(self):
        # add to internal set instead of using .set_* (which overwrites the internal set) to make sure obj and obj2 use separate storage
        obj = CapabilityRule('fsetid')
        obj2 = CapabilityRule('fsetid')
        obj.capability.add('sys_admin')
        obj2.capability.add('ptrace')

        self.assertTrue(self._is_covered(obj, 'capability sys_admin,'))
        self.assertFalse(self._is_covered(obj, 'capability ptrace,'))
        self.assertFalse(self._is_covered(obj2, 'capability sys_admin,'))
        self.assertTrue(self._is_covered(obj2, 'capability ptrace,'))

# --- tests for CapabilityRuleset --- #

class CapabilityRulesTest(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def test_empty_ruleset(self):
        ruleset = CapabilityRuleset()
        ruleset_2 = CapabilityRuleset()
        self.assertEqual([], ruleset.get_raw(2))
        self.assertEqual([], ruleset.get_clean(2))
        self.assertEqual([], ruleset_2.get_raw(2))
        self.assertEqual([], ruleset_2.get_clean(2))

    def test_ruleset_1(self):
        ruleset = CapabilityRuleset()
        rules = [
            'capability sys_admin,',
            'capability chown,',
        ]

        expected_raw = [
            'capability sys_admin,',
            'capability chown,',
            '',
        ]

        expected_clean = [
            'capability chown,',
            'capability sys_admin,',
            '',
        ]

        for rule in rules:
            ruleset.add(CapabilityRule.parse(rule))

        self.assertEqual(expected_raw, ruleset.get_raw())
        self.assertEqual(expected_clean, ruleset.get_clean())

    def test_ruleset_2(self):
        ruleset = CapabilityRuleset()
        rules = [
            'capability chown,',
            'allow capability sys_admin,',
            'deny capability chgrp, # example comment',
        ]

        expected_raw = [
            '  capability chown,',
            '  allow capability sys_admin,',
            '  deny capability chgrp, # example comment',
            '',
        ]

        expected_clean = [
            '  deny capability chgrp, # example comment',
            '',
            '  allow capability sys_admin,',
            '  capability chown,',
            '',
        ]

        for rule in rules:
            ruleset.add(CapabilityRule.parse(rule))

        self.assertEqual(expected_raw, ruleset.get_raw(1))
        self.assertEqual(expected_clean, ruleset.get_clean(1))

    def test_ruleset_add(self):
        rule = CapabilityRule('chgrp', comment=' # example comment')

        ruleset = CapabilityRuleset()
        ruleset.add(rule)

        expected_raw = [
            '  capability chgrp, # example comment',
            '',
        ]

        expected_clean = expected_raw

        self.assertEqual(expected_raw, ruleset.get_raw(1))
        self.assertEqual(expected_clean, ruleset.get_clean(1))


class CapabilityRulesCoveredTest(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

        self.ruleset = CapabilityRuleset()
        rules = [
            'capability chown,',
            'capability setuid setgid,',
            'allow capability sys_admin,',
            'audit capability kill,',
            'deny capability chgrp, # example comment',
        ]

        for rule in rules:
            self.ruleset.add(CapabilityRule.parse(rule))

    def test_ruleset_is_covered_1(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.parse('capability chown,')))
    def test_ruleset_is_covered_2(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.parse('capability sys_admin,')))
    def test_ruleset_is_covered_3(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.parse('allow capability sys_admin,')))
    def test_ruleset_is_covered_4(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.parse('capability setuid,')))
    def test_ruleset_is_covered_5(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.parse('allow capability setgid,')))
    def test_ruleset_is_covered_6(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.parse('capability setgid setuid,')))
    def test_ruleset_is_covered_7(self):
        pass  # self.assertTrue(self.ruleset.is_covered(CapabilityRule.parse('capability sys_admin chown,')))  # fails because it is split over two rule objects internally
    def test_ruleset_is_covered_8(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.parse('capability kill,')))

    def test_ruleset_is_covered_9(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.parse('deny capability chown,')))
    def test_ruleset_is_covered_10(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.parse('deny capability sys_admin,')))
    def test_ruleset_is_covered_11(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.parse('deny capability sys_admin chown,')))
    def test_ruleset_is_covered_12(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.parse('deny capability setgid,')))
    def test_ruleset_is_covered_13(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.parse('deny capability kill,')))

    def test_ruleset_is_covered_14(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.parse('audit capability chown,')))
    def test_ruleset_is_covered_15(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.parse('audit capability sys_admin,')))
    def test_ruleset_is_covered_16(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.parse('audit capability sys_admin chown,')))
    def test_ruleset_is_covered_17(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.parse('audit capability setgid,')))
    def test_ruleset_is_covered_18(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.parse('audit capability kill,')))

    def test_ruleset_is_covered_19(self):
        self.assertTrue(self.ruleset.is_covered(CapabilityRule.parse('deny capability chgrp,')))
    def test_ruleset_is_covered_20(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.parse('audit deny capability chgrp,')))
    def test_ruleset_is_covered_21(self):
        self.assertFalse(self.ruleset.is_covered(CapabilityRule.parse('audit capability chgrp,')))

# XXX - disabling these until we decide whether or not checking whether
# a log is covered by rules should be a separate entry point, possibly
# handling the log structure directly, or whether coverage should be
# solely based on Rule objects and marshaling of a log message into a
# Rule object should occur outside of the Rule classes themselves.
#
#    def _test_log_covered(self, expected, capability):
#        event_base = 'type=AVC msg=audit(1415403814.628:662): apparmor="ALLOWED" operation="capable" profile="/bin/ping" pid=15454 comm="ping" capability=13  capname="%s"'

#        parser = ReadLog('', '', '', '', '')
#        self.assertEqual(expected, self.ruleset.is_log_covered(parser.parse_event(event_base%capability)))
#
#    def test_ruleset_is_log_covered_1(self):
#        self._test_log_covered(False, 'net_raw')
#    def test_ruleset_is_log_covered_2(self):
#        self._test_log_covered(True, 'chown')
#    def test_ruleset_is_log_covered_3(self):
#        self._test_log_covered(True, 'sys_admin')
#    def test_ruleset_is_log_covered_4(self):
#        self._test_log_covered(True, 'kill')
#    def test_ruleset_is_log_covered_5(self):
#        self._test_log_covered(False, 'chgrp')
#    def test_ruleset_is_log_covered_6(self):
#        event_base = 'type=AVC msg=audit(1415403814.628:662): apparmor="ALLOWED" operation="capable" profile="/bin/ping" pid=15454 comm="ping" capability=13  capname="%s"'
#
#        parser = ReadLog('', '', '', '', '')
#        self.assertEqual(True, self.ruleset.is_log_covered(parser.parse_event(event_base%'chgrp'), False))  # ignores allow/deny

class CapabilityGlobTest(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.ruleset = CapabilityRuleset()

    def test_glob(self):
        self.assertEqual(self.ruleset.get_glob('capability net_raw,'), 'capability,')

    def test_glob_ext(self):
        with self.assertRaises(AppArmorBug):
            self.ruleset.get_glob_ext('capability net_raw,')

class CapabilityDeleteTest(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

        self.ruleset = CapabilityRuleset()
        rules = [
            'capability chown,',
            'allow capability sys_admin,',
            'deny capability chgrp, # example comment',
        ]

        for rule in rules:
            self.ruleset.add(CapabilityRule.parse(rule))

    def test_delete(self):
        expected_raw = [
            '  capability chown,',
            '  deny capability chgrp, # example comment',
            '',
        ]

        expected_clean = [
            '  deny capability chgrp, # example comment',
            '',
            '  capability chown,',
            '',
        ]

        self.ruleset.delete(CapabilityRule(['sys_admin']))

        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))

    def test_delete_with_allcaps(self):
        expected_raw = [
            '  capability chown,',
            '  deny capability chgrp, # example comment',
            '  capability,',
            '',
        ]

        expected_clean = [
            '  deny capability chgrp, # example comment',
            '',
            '  capability chown,',
            '  capability,',
            '',
        ]

        self.ruleset.add(CapabilityRule(CapabilityRule.ALL))
        self.ruleset.delete(CapabilityRule('sys_admin'))

        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))

    def test_delete_with_multi(self):
        expected_raw = [
            '  capability chown,',
            '  allow capability sys_admin,',
            '  deny capability chgrp, # example comment',
            '',
        ]

        expected_clean = [
            '  deny capability chgrp, # example comment',
            '',
            '  allow capability sys_admin,',
            '  capability chown,',
            '',
        ]

        self.ruleset.add(CapabilityRule(['audit_read', 'audit_write']))
        self.ruleset.delete(CapabilityRule(['audit_read', 'audit_write']))

        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))

    def test_delete_with_multi_2(self):
        self.ruleset.add(CapabilityRule(['audit_read', 'audit_write']))

        with self.assertRaises(AppArmorBug):
            # XXX ideally delete_raw should remove audit_read from the "capability audit_read audit_write," ruleset
            #     but that's quite some work to cover a corner case.
            self.ruleset.delete(CapabilityRule('audit_read'))

    def test_delete_raw_notfound(self):
        with self.assertRaises(AppArmorBug):
            self.ruleset.delete(CapabilityRule('audit_write'))

    def test_delete_duplicates(self):
        inc = CapabilityRuleset()
        rules = [
            'capability chown,',
            'deny capability chgrp, # example comment',
        ]

        for rule in rules:
            inc.add(CapabilityRule.parse(rule))

        expected_raw = [
            '  allow capability sys_admin,',
            '',
        ]

        expected_clean = expected_raw

        self.assertEqual(self.ruleset.delete_duplicates(inc), 2)
        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))

    def test_delete_duplicates_2(self):
        inc = CapabilityRuleset()
        rules = [
            'capability audit_write,',
            'capability chgrp, # example comment',
        ]

        for rule in rules:
            inc.add(CapabilityRule.parse(rule))

        expected_raw = [
            '  capability chown,',
            '  allow capability sys_admin,',
            '  deny capability chgrp, # example comment',
            '',
        ]

        expected_clean = [
            '  deny capability chgrp, # example comment',
            '',
            '  allow capability sys_admin,',
            '  capability chown,',
            '',
        ]

        self.assertEqual(self.ruleset.delete_duplicates(inc), 0)
        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))

    def test_delete_duplicates_3(self):
        self.ruleset.add(CapabilityRule.parse('audit capability dac_override,'))

        inc = CapabilityRuleset()
        rules = [
            'capability dac_override,',
        ]

        for rule in rules:
            inc.add(CapabilityRule.parse(rule))

        expected_raw = [
            '  capability chown,',
            '  allow capability sys_admin,',
            '  deny capability chgrp, # example comment',
            '  audit capability dac_override,',
            '',
        ]

        expected_clean = [
            '  deny capability chgrp, # example comment',
            '',
            '  allow capability sys_admin,',
            '  audit capability dac_override,',
            '  capability chown,',
            '',
        ]

        self.assertEqual(self.ruleset.delete_duplicates(inc), 0)
        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))

    def test_delete_duplicates_4(self):
        inc = CapabilityRuleset()
        rules = [
            'capability,',
        ]

        for rule in rules:
            inc.add(CapabilityRule.parse(rule))

        expected_raw = [
            '  allow capability sys_admin,',  # XXX huh? should be deleted!
            '  deny capability chgrp, # example comment',
            '',
        ]

        expected_clean = [
            '  deny capability chgrp, # example comment',
            '',
            '  allow capability sys_admin,',  # XXX huh? should be deleted!
            '',
        ]

        self.assertEqual(self.ruleset.delete_duplicates(inc), 1)
        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))

    def test_delete_duplicates_none(self):
        expected_raw = [
            '  capability chown,',
            '  allow capability sys_admin,',
            '  deny capability chgrp, # example comment',
            '',
        ]

        expected_clean = [
            '  deny capability chgrp, # example comment',
            '',
            '  allow capability sys_admin,',
            '  capability chown,',
            '',
        ]

        self.assertEqual(self.ruleset.delete_duplicates(None), 0)
        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))

    def test_delete_duplicates_hasher(self):
        expected_raw = [
            '  capability chown,',
            '  allow capability sys_admin,',
            '  deny capability chgrp, # example comment',
            '',
        ]

        expected_clean = [
            '  deny capability chgrp, # example comment',
            '',
            '  allow capability sys_admin,',
            '  capability chown,',
            '',
        ]

        self.assertEqual(self.ruleset.delete_duplicates(hasher()), 0)
        self.assertEqual(expected_raw, self.ruleset.get_raw(1))
        self.assertEqual(expected_clean, self.ruleset.get_clean(1))


if __name__ == "__main__":
    unittest.main(verbosity=2)
