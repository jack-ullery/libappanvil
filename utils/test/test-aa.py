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
import os
import shutil
import tempfile
from common_test import write_file

from apparmor.aa import check_for_apparmor, is_skippable_file

class AaTest_check_for_apparmor(unittest.TestCase):
    FILESYSTEMS_WITH_SECURITYFS = 'nodev\tdevtmpfs\nnodev\tsecurityfs\nnodev\tsockfs\n\text3\n\text2\n\text4'
    FILESYSTEMS_WITHOUT_SECURITYFS = 'nodev\tdevtmpfs\nnodev\tsockfs\n\text3\n\text2\n\text4'

    MOUNTS_WITH_SECURITYFS = ( 'proc /proc proc rw,relatime 0 0\n'
        'securityfs %s/security securityfs rw,nosuid,nodev,noexec,relatime 0 0\n'
        '/dev/sda1 / ext3 rw,noatime,data=ordered 0 0' )

    MOUNTS_WITHOUT_SECURITYFS = ( 'proc /proc proc rw,relatime 0 0\n'
        '/dev/sda1 / ext3 rw,noatime,data=ordered 0 0' )

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='aa-py-')

    def tearDown(self):
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def test_check_for_apparmor_None_1(self):
        filesystems = write_file(self.tmpdir, 'filesystems', self.FILESYSTEMS_WITHOUT_SECURITYFS)
        mounts = write_file(self.tmpdir, 'mounts', self.MOUNTS_WITH_SECURITYFS)
        self.assertEqual(None, check_for_apparmor(filesystems, mounts))

    def test_check_for_apparmor_None_2(self):
        filesystems = write_file(self.tmpdir, 'filesystems', self.FILESYSTEMS_WITHOUT_SECURITYFS)
        mounts = write_file(self.tmpdir, 'mounts', self.MOUNTS_WITHOUT_SECURITYFS)
        self.assertEqual(None, check_for_apparmor(filesystems, mounts))

    def test_check_for_apparmor_None_3(self):
        filesystems = write_file(self.tmpdir, 'filesystems', self.FILESYSTEMS_WITH_SECURITYFS)
        mounts = write_file(self.tmpdir, 'mounts', self.MOUNTS_WITHOUT_SECURITYFS)
        self.assertEqual(None, check_for_apparmor(filesystems, mounts))

    def test_check_for_apparmor_securityfs_invalid_filesystems(self):
        filesystems = ''
        mounts = write_file(self.tmpdir, 'mounts', self.MOUNTS_WITH_SECURITYFS % self.tmpdir)
        self.assertEqual(None, check_for_apparmor(filesystems, mounts))

    def test_check_for_apparmor_securityfs_invalid_mounts(self):
        filesystems = write_file(self.tmpdir, 'filesystems', self.FILESYSTEMS_WITH_SECURITYFS)
        mounts = ''
        self.assertEqual(None, check_for_apparmor(filesystems, mounts))

    def test_check_for_apparmor_invalid_securityfs_path(self):
        filesystems = write_file(self.tmpdir, 'filesystems', self.FILESYSTEMS_WITH_SECURITYFS)
        mounts = write_file(self.tmpdir, 'mounts', self.MOUNTS_WITH_SECURITYFS % 'xxx')
        self.assertEqual(None, check_for_apparmor(filesystems, mounts))

    def test_check_for_apparmor_securityfs_mounted(self):
        filesystems = write_file(self.tmpdir, 'filesystems', self.FILESYSTEMS_WITH_SECURITYFS)
        mounts = write_file(self.tmpdir, 'mounts', self.MOUNTS_WITH_SECURITYFS % self.tmpdir)
        self.assertEqual('%s/security/apparmor' % self.tmpdir, check_for_apparmor(filesystems, mounts))

class AaTest_is_skippable_file(unittest.TestCase):
    def test_not_skippable_01(self):
        self.assertFalse(is_skippable_file('bin.ping'))
    def test_not_skippable_02(self):
        self.assertFalse(is_skippable_file('usr.lib.dovecot.anvil'))
    def test_not_skippable_03(self):
        self.assertFalse(is_skippable_file('bin.~ping'))
    def test_not_skippable_04(self):
        self.assertFalse(is_skippable_file('bin.rpmsave.ping'))
    def test_not_skippable_05(self):
        # normally is_skippable_file should be called without directory, but it shouldn't hurt too much
        self.assertFalse(is_skippable_file('/etc/apparmor.d/bin.ping'))
    def test_not_skippable_06(self):
        self.assertFalse(is_skippable_file('bin.pingrej'))

    def test_skippable_01(self):
        self.assertTrue(is_skippable_file('bin.ping.dpkg-new'))
    def test_skippable_02(self):
        self.assertTrue(is_skippable_file('bin.ping.dpkg-old'))
    def test_skippable_03(self):
        self.assertTrue(is_skippable_file('bin.ping..dpkg-dist'))
    def test_skippable_04(self):
        self.assertTrue(is_skippable_file('bin.ping..dpkg-bak'))
    def test_skippable_05(self):
        self.assertTrue(is_skippable_file('bin.ping.rpmnew'))
    def test_skippable_06(self):
        self.assertTrue(is_skippable_file('bin.ping.rpmsave'))
    def test_skippable_07(self):
        self.assertTrue(is_skippable_file('bin.ping.orig'))
    def test_skippable_08(self):
        self.assertTrue(is_skippable_file('bin.ping.rej'))
    def test_skippable_09(self):
        self.assertTrue(is_skippable_file('bin.ping~'))
    def test_skippable_10(self):
        self.assertTrue(is_skippable_file('.bin.ping'))
    def test_skippable_11(self):
        self.assertTrue(is_skippable_file(''))  # empty filename
    def test_skippable_12(self):
        self.assertTrue(is_skippable_file('/etc/apparmor.d/'))  # directory without filename
    def test_skippable_13(self):
        self.assertTrue(is_skippable_file('README'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
