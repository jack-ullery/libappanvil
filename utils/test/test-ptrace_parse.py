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

class AAParsePtraceTest(unittest.TestCase):

    def _test_parse_ptrace_rule(self, rule):
        ptrace = aa.parse_ptrace_rule(rule)
        self.assertEqual(rule, ptrace.serialize(),
                'ptrace object returned "%s", expected "%s"' % (ptrace.serialize(), rule))

    def test_parse_plain_ptrace_rule(self):
        self._test_parse_ptrace_rule('ptrace,')

    def test_parse_readby_ptrace_rule(self):
        self._test_parse_ptrace_rule('ptrace (readby),')

    def test_parse_trace_ptrace_rule(self):
        self._test_parse_ptrace_rule('ptrace (trace),')

    def test_parse_trace_read_ptrace_rule(self):
        self._test_parse_ptrace_rule('ptrace (trace read),')

    def test_parse_r_ptrace_rule(self):
        self._test_parse_ptrace_rule('ptrace r,')

    def test_parse_w_ptrace_rule(self):
        self._test_parse_ptrace_rule('ptrace w,')

    def test_parse_rw_ptrace_rule(self):
        self._test_parse_ptrace_rule('ptrace rw,')

    def test_parse_peer_1_ptrace_rule(self):
        self._test_parse_ptrace_rule('ptrace read peer=foo,')

    def test_parse_peer_2_ptrace_rule(self):
        self._test_parse_ptrace_rule('ptrace (trace read) peer=/usr/bin/bar,')

    def test_parse_peer_3_ptrace_rule(self):
        self._test_parse_ptrace_rule('ptrace wr peer=/sbin/baz,')

if __name__ == '__main__':
    unittest.main()
