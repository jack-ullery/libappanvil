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

from apparmor.rule.signal import SignalRule

class AAParseSignalTest(AATest):
    def _run_test(self, params, expected):
        parsed = SignalRule.parse(params)
        self.assertEqual(expected, parsed.get_clean())


    tests = [
        ('signal,',                     'signal,'),
        ('signal (receive),',           'signal receive,'),
        ('signal (send),',              'signal send,'),
        ('signal (send receive),',      'signal (receive send),'),
        ('signal r,',                   'signal r,'),
        ('signal w,',                   'signal w,'),
        ('signal rw,',                  'signal rw,'),
        ('signal send set=("hup"),',    'signal send set=hup,'),
        ('signal (receive) set=kill,',  'signal receive set=kill,'),
        ('signal w set=(quit int),',    'signal w set=(int quit),'),
        ('signal receive peer=foo,',    'signal receive peer=foo,'),
        ('signal (send receive) peer=/usr/bin/bar,',    'signal (receive send) peer=/usr/bin/bar,'),
        ('signal wr set=(pipe, usr1) peer=/sbin/baz,',  'signal wr set=(pipe usr1) peer=/sbin/baz,'),
    ]


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=2)
