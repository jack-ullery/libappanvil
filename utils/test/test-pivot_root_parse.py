#! /usr/bin/env python
# ------------------------------------------------------------------
#
#    Copyright (C) 2014 Canonical Ltd.
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import apparmor.aa as aa
import unittest

class AAParsePivotRootTest(unittest.TestCase):

    def _test_parse_pivot_root_rule(self, rule):
        pivot_root = aa.parse_pivot_root_rule(rule)
        self.assertEqual(rule, pivot_root.serialize(),
                'pivot_root object returned "%s", expected "%s"' % (pivot_root.serialize(), rule))

    def test_parse_plain_pivot_root_rule(self):
        self._test_parse_pivot_root_rule('pivot_root,')

    def test_parse_old_pivot_root_rule(self):
        self._test_parse_pivot_root_rule('pivot_root /old,')

    def test_parse_new_pivot_root_rule(self):
        self._test_parse_pivot_root_rule('pivot_root /old /new,')

    def test_parse_child_pivot_root_rule(self):
        self._test_parse_pivot_root_rule('pivot_root /old /new -> /usr/bin/child,')

if __name__ == '__main__':
    unittest.main()
