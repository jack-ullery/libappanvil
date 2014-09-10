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
from common_test import AAParseTest, setup_regex_tests

class AAParsePtraceTest(AAParseTest):
    def setUp(self):
        self.parse_function = aa.parse_ptrace_rule

    tests = [
        ('ptrace,', 'ptrace base keyword rule'),
        ('ptrace (readby),', 'ptrace readby rule'),
        ('ptrace (trace),', 'ptrace trace rule'),
        ('ptrace (trace read),', 'ptrace multi-perm rule'),
        ('ptrace r,', 'ptrace r rule'),
        ('ptrace w,', 'ptrace w rule'),
        ('ptrace rw,', 'ptrace rw rule'),
        ('ptrace read peer=foo,', 'ptrace peer rule 1'),
        ('ptrace (trace read) peer=/usr/bin/bar,', 'ptrace peer rule 2'),
        ('ptrace wr peer=/sbin/baz,', 'ptrace peer rule 3'),
    ]

if __name__ == '__main__':
    setup_regex_tests(AAParsePtraceTest)
    unittest.main(verbosity=2)
