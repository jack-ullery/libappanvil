#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2015 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import re
import unittest

import apparmor.severity as severity
from apparmor.common import AppArmorBug
from apparmor.rule import BaseRule, parse_modifiers
from common_test import AATest, setup_all_loops


class TestBaserule(AATest):

    class ValidSubclass(BaseRule):
        @classmethod
        def _match(cls, raw_rule): pass

        @classmethod
        def _create_instance(cls, raw_rule): pass

        def get_clean(self, depth=0): pass

        def is_covered_localvars(self, other_rule): pass

        def is_equal_localvars(self, other_rule, strict): pass

        def logprof_header_localvars(self): pass

    def test_implemented_abstract_methods(self):
        self.ValidSubclass()

    def test_unimplemented_abstract_methods(self):
        with self.assertRaises(TypeError):
            BaseRule()

        class InvalidSubclass(BaseRule):
            pass

        with self.assertRaises(TypeError):
            InvalidSubclass()

    def test_abstract__create_instance(self):
        with self.assertRaises(NotImplementedError):
            BaseRule._create_instance('foo')

    def test_abstract__create_instance_2(self):
        with self.assertRaises(NotImplementedError):
            BaseRule.create_instance('foo')

    def test_abstract__match(self):
        with self.assertRaises(NotImplementedError):
            BaseRule._match('foo')

    def test_abstract__match2(self):
        with self.assertRaises(NotImplementedError):
            BaseRule.match('foo')

    def test_parse_modifiers_invalid(self):
        regex = re.compile('^\s*(?P<audit>audit\s+)?(?P<allow>allow\s+|deny\s+|invalid\s+)?')
        matches = regex.search('audit invalid ')

        with self.assertRaises(AppArmorBug):
            parse_modifiers(matches)

    def test_default_severity(self):
        sev_db = severity.Severity('../severity.db', 'unknown')
        obj = self.ValidSubclass()
        rank = obj.severity(sev_db)
        self.assertEqual(rank, sev_db.NOT_IMPLEMENTED)

    def test_edit_header_localvars(self):
        obj = self.ValidSubclass()
        with self.assertRaises(NotImplementedError):
            obj.edit_header()

    def test_validate_edit_localvars(self):
        obj = self.ValidSubclass()
        with self.assertRaises(NotImplementedError):
            obj.validate_edit('/foo')

    def test_store_edit_localvars(self):
        obj = self.ValidSubclass()
        with self.assertRaises(NotImplementedError):
            obj.store_edit('/foo')


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
