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

import unittest
from common_test import AATest, setup_all_loops

from apparmor.rule.ptrace import PtraceRule

class AAParsePtraceTest(AATest):
    def _run_test(self, params, expected):
        rule_obj = PtraceRule.parse(params)
        self.assertEqual(rule_obj.get_clean(), expected)

    tests = [
        ('ptrace,',                 'ptrace,'),
        ('ptrace (readby),',        'ptrace readby,'),
        ('ptrace (trace),',         'ptrace trace,'),
        ('ptrace (trace read),',    'ptrace (read trace),'),
        ('ptrace r,',               'ptrace r,'),
        ('ptrace w,',               'ptrace w,'),
        ('ptrace rw,',              'ptrace rw,'),
        ('ptrace read peer=foo,',   'ptrace read peer=foo,'),
        ('ptrace (trace read) peer=/usr/bin/bar,', 'ptrace (read trace) peer=/usr/bin/bar,'),
        ('ptrace wr peer=/sbin/baz,',   'ptrace wr peer=/sbin/baz,'),
    ]

setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=2)
