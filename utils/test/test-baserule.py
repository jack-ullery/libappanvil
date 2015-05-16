#! /usr/bin/env python
# ------------------------------------------------------------------
#
#    Copyright (C) 2015 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import unittest
from common_test import AATest, setup_all_loops

from apparmor.common import AppArmorBug
from apparmor.rule import BaseRule, parse_modifiers

import re

class TestBaserule(AATest):
    def test_abstract__parse(self):
        with self.assertRaises(AppArmorBug):
            BaseRule._parse('foo')

    def test_abstract__parse_2(self):
        with self.assertRaises(AppArmorBug):
            BaseRule.parse('foo')

    def test_abstract__match(self):
        with self.assertRaises(AppArmorBug):
            BaseRule._match('foo')

    def test_abstract__match2(self):
        with self.assertRaises(AppArmorBug):
            BaseRule.match('foo')

    def test_is_equal_localvars(self):
        obj = BaseRule()
        with self.assertRaises(AppArmorBug):
            obj.is_equal_localvars(BaseRule())

    def test_is_covered_localvars(self):
        obj = BaseRule()
        with self.assertRaises(AppArmorBug):
            obj.is_covered_localvars(None)

    def test_parse_modifiers_invalid(self):
        regex = re.compile('^\s*(?P<audit>audit\s+)?(?P<allow>allow\s+|deny\s+|invalid\s+)?')
        matches = regex.search('audit invalid ')

        with self.assertRaises(AppArmorBug):
            parse_modifiers(matches)



setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=2)
