#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2017 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import unittest
from common_test import AATest, setup_all_loops

from apparmor.common import AppArmorBug
from apparmor.profile_storage import ProfileStorage, var_transform

class TestUnknownKey(AATest):
    def AASetup(self):
        self.storage = ProfileStorage('/test/foo', 'hat', 'TEST')

    def test_read(self):
        with self.assertRaises(AppArmorBug):
            self.storage['foo']

    def test_get(self):
        with self.assertRaises(AppArmorBug):
            self.storage.get('foo')

    def test_get_with_fallback(self):
        with self.assertRaises(AppArmorBug):
            self.storage.get('foo', 'bar')

    def test_set(self):
        with self.assertRaises(AppArmorBug):
            self.storage['foo'] = 'bar'

class AaTest_var_transform(AATest):
    tests = [
        (['foo', ''],           '"" foo'        ),
        (['foo', 'bar'],        'bar foo'       ),
        ([''],                  '""'            ),
        (['bar baz', 'foo'],    '"bar baz" foo' ),
    ]

    def _run_test(self, params, expected):
        self.assertEqual(var_transform(params), expected)


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
