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

class AAParseUnixTest(unittest.TestCase):

    def _test_parse_unix_rule(self, rule):
        unix = aa.parse_unix_rule(rule)
        self.assertEqual(rule, unix.serialize(),
                'ptrace object returned "%s", expected "%s"' % (unix.serialize(), rule))

    def test_parse_plain_unix_rule(self):
        self._test_parse_unix_rule('unix,')

    def test_parse_r_unix_rule(self):
        self._test_parse_unix_rule('unix r,')

    def test_parse_w_unix_rule(self):
        self._test_parse_unix_rule('unix w,')

    def test_parse_rw_unix_rule(self):
        self._test_parse_unix_rule('unix rw,')

    def test_parse_send_unix_rule(self):
        self._test_parse_unix_rule('unix send,')

    def test_parse_receive_unix_rule(self):
        self._test_parse_unix_rule('unix receive,')

    def test_parse_r_paren_unix_rule(self):
        self._test_parse_unix_rule('unix (r),')

    def test_parse_w_paren_unix_rule(self):
        self._test_parse_unix_rule('unix (w),')

    def test_parse_rw_paren_unix_rule(self):
        self._test_parse_unix_rule('unix (rw),')

    def test_parse_send_paren_unix_rule(self):
        self._test_parse_unix_rule('unix (send),')

    def test_parse_receive_paren_unix_rule(self):
        self._test_parse_unix_rule('unix (receive),')

    def test_parse_complex_unix_rule(self):
        self._test_parse_unix_rule('unix (connect, receive, send) type=stream peer=(label=unconfined,addr="@/tmp/.X11-unix/X[0-9]*"),')

if __name__ == '__main__':
    unittest.main(verbosity=2)
