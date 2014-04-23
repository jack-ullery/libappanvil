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

class AAParseSignalTest(unittest.TestCase):

    def _test_parse_signal_rule(self, rule):
        signal = aa.parse_signal_rule(rule)
        self.assertEqual(rule, signal.serialize(),
                'signal object returned "%s", expected "%s"' % (signal.serialize(), rule))

    def test_parse_plain_signal_rule(self):
        self._test_parse_signal_rule('signal,')

    def test_parse_receive_signal_rule(self):
        self._test_parse_signal_rule('signal (receive),')

    def test_parse_send_signal_rule(self):
        self._test_parse_signal_rule('signal (send),')

    def test_parse_send_receive_signal_rule(self):
        self._test_parse_signal_rule('signal (send receive),')

    def test_parse_r_signal_rule(self):
        self._test_parse_signal_rule('signal r,')

    def test_parse_w_signal_rule(self):
        self._test_parse_signal_rule('signal w,')

    def test_parse_rw_signal_rule(self):
        self._test_parse_signal_rule('signal rw,')

    def test_parse_set_1_signal_rule(self):
        self._test_parse_signal_rule('signal send set=("hup"),')

    def test_parse_set_2_signal_rule(self):
        self._test_parse_signal_rule('signal (receive) set=kill,')

    def test_parse_set_3_signal_rule(self):
        self._test_parse_signal_rule('signal w set=(quit int),')

    def test_parse_peer_1_signal_rule(self):
        self._test_parse_signal_rule('signal receive peer=foo,')

    def test_parse_peer_2_signal_rule(self):
        self._test_parse_signal_rule('signal (send receive) peer=/usr/bin/bar,')

    def test_parse_peer_3_signal_rule(self):
        self._test_parse_signal_rule('signal wr set=(pipe, usr1) peer=/sbin/baz,')

if __name__ == '__main__':
    unittest.main()
