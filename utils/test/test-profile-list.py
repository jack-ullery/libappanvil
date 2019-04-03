#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2018 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import unittest
from common_test import AATest, setup_all_loops

from apparmor.common import AppArmorBug, AppArmorException
from apparmor.profile_list import ProfileList

class TestAdd(AATest):
    def AASetup(self):
        self.pl = ProfileList()

    def testEmpty(self):
        self.assertEqual(self.pl.profile_names, {})
        self.assertEqual(self.pl.attachments, {})

    def testAdd_1(self):
        self.pl.add('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo')
        self.assertEqual(self.pl.profile_names, {'foo': '/etc/apparmor.d/bin.foo'})
        self.assertEqual(self.pl.attachments, {'/bin/foo': '/etc/apparmor.d/bin.foo'})

    def testAdd_2(self):
        self.pl.add('/etc/apparmor.d/bin.foo', None, '/bin/foo')
        self.assertEqual(self.pl.profile_names, {})
        self.assertEqual(self.pl.attachments, {'/bin/foo': '/etc/apparmor.d/bin.foo'})

    def testAdd_3(self):
        self.pl.add('/etc/apparmor.d/bin.foo', 'foo', None)
        self.assertEqual(self.pl.profile_names, {'foo': '/etc/apparmor.d/bin.foo'})
        self.assertEqual(self.pl.attachments, {})


    def testAddError_1(self):
        with self.assertRaises(AppArmorBug):
            self.pl.add('', 'foo', '/bin/foo')  # no filename

    def testAddError_2(self):
        with self.assertRaises(AppArmorBug):
            self.pl.add('/etc/apparmor.d/bin.foo', None, None)  # neither attachment or profile name

    def testAddError_twice_1(self):
        self.pl.add('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo')
        with self.assertRaises(AppArmorException):
            self.pl.add('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo')

    def testAddError_twice_2(self):
        self.pl.add('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo')
        with self.assertRaises(AppArmorException):
            self.pl.add('/etc/apparmor.d/bin.foo', 'foo', None)

    def testAddError_twice_3(self):
        self.pl.add('/etc/apparmor.d/bin.foo', None, '/bin/foo')
        with self.assertRaises(AppArmorException):
            self.pl.add('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo')

    def testAddError_twice_4(self):
        self.pl.add('/etc/apparmor.d/bin.foo', None, '/bin/foo')
        with self.assertRaises(AppArmorException):
            self.pl.add('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo')

    def testAddError_twice_5(self):
        self.pl.add('/etc/apparmor.d/bin.foo', 'foo', None)
        with self.assertRaises(AppArmorException):
            self.pl.add('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo')

class TestFilename_from_profile_name(AATest):
    tests = [
        ('foo',         '/etc/apparmor.d/bin.foo'),
        ('/bin/foo',    None),
        ('bar',         None),
        ('/usr{,{/lib,/lib32,/lib64}/wine}/bin/wine{,-preloader,server}{,-staging-*,-vanilla-*}',   '/etc/apparmor.d/usr.bin.wine'),
        ('/usr/lib/wine/bin/wine-preloader-staging-foo',                                            None),  # no AARE matching for profile names
    ]

    def AASetup(self):
        self.pl = ProfileList()
        self.pl.add('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo')
        self.pl.add('/etc/apparmor.d/usr.bin.wine', '/usr{,{/lib,/lib32,/lib64}/wine}/bin/wine{,-preloader,server}{,-staging-*,-vanilla-*}', '/usr{,{/lib,/lib32,/lib64}/wine}/bin/wine{,-preloader,server}{,-staging-*,-vanilla-*}')

    def _run_test(self, params, expected):
        self.assertEqual(self.pl.filename_from_profile_name(params), expected)

class TestFilename_from_attachment(AATest):
    tests = [
        ('/bin/foo',    '/etc/apparmor.d/bin.foo'),
        ('/bin/baz',    '/etc/apparmor.d/bin.baz'),
        ('/bin/foobar', '/etc/apparmor.d/bin.foobar'),
        ('@{foo}',      None),  # XXX variables not supported yet (and @{foo} isn't defined in this test)
        ('/bin/404',    None),
        ('/usr{,{/lib,/lib32,/lib64}/wine}/bin/wine{,-preloader,server}{,-staging-*,-vanilla-*}',   '/etc/apparmor.d/usr.bin.wine'),  # XXX should this really match, or should attachment matching only use AARE?
        ('/usr/lib/wine/bin/wine-preloader-staging-foo',                                            '/etc/apparmor.d/usr.bin.wine'),  # AARE match
    ]

    def AASetup(self):
        self.pl = ProfileList()
        self.pl.add('/etc/apparmor.d/bin.foo', 'foo', '/bin/foo')
        self.pl.add('/etc/apparmor.d/bin.baz', 'baz', '/bin/ba*')
        self.pl.add('/etc/apparmor.d/bin.foobar', 'foobar', '/bin/foo{bar,baz}')
        self.pl.add('/etc/apparmor.d/usr.bin.wine', '/usr{,{/lib,/lib32,/lib64}/wine}/bin/wine{,-preloader,server}{,-staging-*,-vanilla-*}', '/usr{,{/lib,/lib32,/lib64}/wine}/bin/wine{,-preloader,server}{,-staging-*,-vanilla-*}')

    def _run_test(self, params, expected):
        self.assertEqual(self.pl.filename_from_attachment(params), expected)

    def test_non_path_attachment(self):
        with self.assertRaises(AppArmorBug):
            self.pl.filename_from_attachment('foo')


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
