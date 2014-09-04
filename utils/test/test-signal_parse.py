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

class AAParseSignalTest(AAParseTest):
    def setUp(self):
        self.parse_function = aa.parse_signal_rule

    tests = [
        ('signal,', 'signal base keyword rule'),
        ('signal (receive),', 'signal receive rule'),
        ('signal (send),', 'signal send rule'),
        ('signal (send receive),', 'signal multiple perms rule'),
        ('signal r,', 'signal r rule'),
        ('signal w,', 'signal w rule'),
        ('signal rw,', 'signal rw rule'),
        ('signal send set=("hup"),', 'signal set rule 1'),
        ('signal (receive) set=kill,', 'signal set rule 2'),
        ('signal w set=(quit int),', 'signal set rule 3'),
        ('signal receive peer=foo,', 'signal peer rule 1'),
        ('signal (send receive) peer=/usr/bin/bar,', 'signal peer rule 2'),
        ('signal wr set=(pipe, usr1) peer=/sbin/baz,', 'signal peer rule 3'),
    ]

if __name__ == '__main__':
    setup_regex_tests(AAParseSignalTest)
    unittest.main(verbosity=2)
