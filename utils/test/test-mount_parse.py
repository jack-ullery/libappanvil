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

class AAParseMountTest(unittest.TestCase):

    def test_parse_plain_mount_rule(self):
        rule = 'mount,'
        mount = aa.parse_mount_rule(rule)
        self.assertEqual(rule, mount.serialize(),
                'mount object returned "%s", expected "%s"' % (mount.serialize(), rule))

    def test_parse_ro_mount(self):
        rule = 'mount -o ro,'
        mount = aa.parse_mount_rule(rule)
        self.assertEqual(rule, mount.serialize(),
                'mount object returned "%s", expected "%s"' % (mount.serialize(), rule))

    def test_parse_rw_mount_with_mount_points(self):
        rule = 'mount -o rw /dev/sdb1 -> /mnt/external,'
        mount = aa.parse_mount_rule(rule)
        self.assertEqual(rule, mount.serialize(),
                'mount object returned "%s", expected "%s"' % (mount.serialize(), rule))

class AAParseRemountTest(unittest.TestCase):

    def test_parse_plain_remount_rule(self):
        rule = 'remount,'
        mount = aa.parse_mount_rule(rule)
        self.assertEqual(rule, mount.serialize(),
                'mount object returned "%s", expected "%s"' % (mount.serialize(), rule))

    def test_parse_ro_remount(self):
        rule = 'remount -o ro,'
        mount = aa.parse_mount_rule(rule)
        self.assertEqual(rule, mount.serialize(),
                'mount object returned "%s", expected "%s"' % (mount.serialize(), rule))

    def test_parse_ro_remount_with_mount_point(self):
        rule = 'remount -o ro /,'
        mount = aa.parse_mount_rule(rule)
        self.assertEqual(rule, mount.serialize(),
                'mount object returned "%s", expected "%s"' % (mount.serialize(), rule))

class AAParseUmountTest(unittest.TestCase):

    def test_parse_plain_umount_rule(self):
        rule = 'umount,'
        mount = aa.parse_mount_rule(rule)
        self.assertEqual(rule, mount.serialize(),
                'mount object returned "%s", expected "%s"' % (mount.serialize(), rule))

    def test_parse_umount_with_mount_point(self):
        rule = 'umount /mnt/external,'
        mount = aa.parse_mount_rule(rule)
        self.assertEqual(rule, mount.serialize(),
                'mount object returned "%s", expected "%s"' % (mount.serialize(), rule))

if __name__ == '__main__':
    unittest.main()
