#! /usr/bin/env python
# ------------------------------------------------------------------
#
#    Copyright (C) 2014 Christian Boltz
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import unittest

from apparmor.aamode import split_log_mode, sub_str_to_mode
from apparmor.common import AppArmorBug

class AamodeTest_split_log_mode(unittest.TestCase):
    def test_split_log_mode_1(self):
        self.assertEqual(split_log_mode(''), ('', ''))
    def test_split_log_mode_2(self):
        self.assertEqual(split_log_mode('r'), ('r', 'r'))
    def test_split_log_mode_3(self):
        self.assertEqual(split_log_mode('r::'), ('r', ''))
    def test_split_log_mode_4(self):
        self.assertEqual(split_log_mode('::r'), ('', 'r'))
    def test_split_log_mode_5(self):
        self.assertEqual(split_log_mode('r::w'), ('r', 'w'))
    def test_split_log_mode_6(self):
        self.assertEqual(split_log_mode('rw::rw'), ('rw', 'rw'))
    def test_split_log_mode_invalid_1(self):
        with self.assertRaises(AppArmorBug):
            split_log_mode('r::w::r')

class AamodeTest_sub_str_to_mode(unittest.TestCase):
    def test_sub_str_to_mode_1(self):
        self.assertEqual(sub_str_to_mode(''), set())
    def test_sub_str_to_mode_2(self):
        self.assertEqual(sub_str_to_mode('ix'), {'i', 'x'})
    def test_sub_str_to_mode_3(self):
        self.assertEqual(sub_str_to_mode('rw'), {'r', 'w'})
    def test_sub_str_to_mode_4(self):
        self.assertEqual(sub_str_to_mode('rPix'), {'i', 'P', 'r', 'x'})
    def test_sub_str_to_mode_5(self):
        self.assertEqual(sub_str_to_mode('rPUx'), {'P', 'r', 'U', 'x'})
    def test_sub_str_to_mode_6(self):
        self.assertEqual(sub_str_to_mode('cix'), {'i', 'x', 'C', 'execunsafe'})
    def test_sub_str_to_mode_7(self):
        self.assertEqual(sub_str_to_mode('rwlk'), {'k', 'r', 'l', 'w'})
    def test_sub_str_to_mode_8(self):
        self.assertEqual(sub_str_to_mode('asdf42'), {'a'})
    def test_sub_str_to_mode_dupes(self):
        self.assertEqual(sub_str_to_mode('rwrwrw'), {'r', 'w'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
