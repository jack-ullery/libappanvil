#! /usr/bin/env python
# ------------------------------------------------------------------
#
#    Copyright (C) 2014-2015 Christian Boltz
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import unittest
from common_test import AATest, setup_all_tests
import os
import shutil
import tempfile
from common_test import read_file, write_file

from apparmor.aa import check_for_apparmor, get_profile_flags, set_profile_flags, is_skippable_file, parse_profile_start, write_header, serialize_parse_profile_start
from apparmor.common import AppArmorException, AppArmorBug

class AaTestWithTempdir(AATest):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='aa-py-')

    def tearDown(self):
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)


class AaTest_check_for_apparmor(AaTestWithTempdir):
    FILESYSTEMS_WITH_SECURITYFS = 'nodev\tdevtmpfs\nnodev\tsecurityfs\nnodev\tsockfs\n\text3\n\text2\n\text4'
    FILESYSTEMS_WITHOUT_SECURITYFS = 'nodev\tdevtmpfs\nnodev\tsockfs\n\text3\n\text2\n\text4'

    MOUNTS_WITH_SECURITYFS = ( 'proc /proc proc rw,relatime 0 0\n'
        'securityfs %s/security securityfs rw,nosuid,nodev,noexec,relatime 0 0\n'
        '/dev/sda1 / ext3 rw,noatime,data=ordered 0 0' )

    MOUNTS_WITHOUT_SECURITYFS = ( 'proc /proc proc rw,relatime 0 0\n'
        '/dev/sda1 / ext3 rw,noatime,data=ordered 0 0' )

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

class AaTest_get_profile_flags(AaTestWithTempdir):
    def _test_get_flags(self, profile_header, expected_flags):
        file = write_file(self.tmpdir, 'profile', '%s {\n}\n' % profile_header)
        flags = get_profile_flags(file, '/foo')
        self.assertEqual(flags, expected_flags)

    def test_get_flags_01(self):
        self._test_get_flags('/foo', None)
    def test_get_flags_02(self):
        self._test_get_flags('/foo (  complain  )', '  complain  ')
    def test_get_flags_04(self):
        self._test_get_flags('/foo (complain)', 'complain')
    def test_get_flags_05(self):
        self._test_get_flags('/foo flags=(complain)', 'complain')
    def test_get_flags_06(self):
        self._test_get_flags('/foo flags=(complain,  audit)', 'complain,  audit')

    def test_get_flags_invalid_01(self):
        with self.assertRaises(AppArmorBug):
            self._test_get_flags('/foo ()', None)
    def test_get_flags_invalid_02(self):
        with self.assertRaises(AppArmorBug):
            self._test_get_flags('/foo flags=()', None)
    def test_get_flags_invalid_03(self):
        with self.assertRaises(AppArmorException):
            self._test_get_flags('/foo (  )', '  ')

    def test_get_flags_other_profile(self):
        with self.assertRaises(AppArmorException):
            self._test_get_flags('/no-such-profile flags=(complain)', 'complain')

class AaTest_set_profile_flags(AaTestWithTempdir):
    def _test_set_flags(self, profile, old_flags, new_flags, whitespace='', comment='', more_rules='',
                        expected_flags='@-@-@', check_new_flags=True, profile_name='/foo'):
        if old_flags:
            old_flags = ' %s' % old_flags

        if expected_flags == '@-@-@':
            expected_flags = new_flags

        if expected_flags:
            expected_flags = ' flags=(%s)' % (expected_flags)
        else:
            expected_flags = ''

        if comment:
            comment = ' %s' % comment

        dummy_profile_content = '  #include <abstractions/base>\n  capability chown,\n  /bar r,'
        prof_template = '%s%s%s {%s\n%s\n%s\n}\n'
        old_prof = prof_template % (whitespace, profile, old_flags,      comment, more_rules, dummy_profile_content)
        new_prof = prof_template % (whitespace, profile, expected_flags, comment, more_rules, dummy_profile_content)

        self.file = write_file(self.tmpdir, 'profile', old_prof)
        set_profile_flags(self.file, profile_name, new_flags)
        if check_new_flags:
            real_new_prof = read_file(self.file)
            self.assertEqual(new_prof, real_new_prof)

    # tests that actually don't change the flags
    def test_set_flags_nochange_01(self):
        self._test_set_flags('/foo', '', '')
    def test_set_flags_nochange_02(self):
        self._test_set_flags('/foo', '(  complain  )', '  complain  ', whitespace='   ')
    def test_set_flags_nochange_03(self):
        self._test_set_flags('/foo', '(complain)', 'complain')
    def test_set_flags_nochange_04(self):
        self._test_set_flags('/foo', 'flags=(complain)', 'complain')
    def test_set_flags_nochange_05(self):
        self._test_set_flags('/foo', 'flags=(complain,  audit)', 'complain,  audit', whitespace='     ')
    def test_set_flags_nochange_06(self):
        self._test_set_flags('/foo', 'flags=(complain,  audit)', 'complain,  audit', whitespace='     ', comment='# a comment')
    def test_set_flags_nochange_07(self):
        self._test_set_flags('/foo', 'flags=(complain,  audit)', 'complain,  audit', whitespace='     ', more_rules='  # a comment\n#another  comment')
    def test_set_flags_nochange_08(self):
        self._test_set_flags('profile /foo', 'flags=(complain)', 'complain')
    def test_set_flags_nochange_09(self):
        self._test_set_flags('profile xy /foo', 'flags=(complain)', 'complain', profile_name='xy')
    def test_set_flags_nochange_10(self):
        self._test_set_flags('profile "/foo bar"', 'flags=(complain)', 'complain', profile_name='/foo bar')
    def test_set_flags_nochange_11(self):
        self._test_set_flags('/foo', '(complain)', 'complain', profile_name=None)
    #def test_set_flags_nochange_12(self):
    # XXX changes the flags for the child profile (which happens to have the same profile name) to 'complain'
    #    self._test_set_flags('/foo', 'flags=(complain)', 'complain', more_rules='  profile /foo {\n}')

    # tests that change the flags
    def test_set_flags_01(self):
        self._test_set_flags('/foo', '', 'audit')
    def test_set_flags_02(self):
        self._test_set_flags('/foo', '(  complain  )', 'audit ', whitespace='  ')
    def test_set_flags_04(self):
        self._test_set_flags('/foo', '(complain)', 'audit')
    def test_set_flags_05(self):
        self._test_set_flags('/foo', 'flags=(complain)', 'audit')
    def test_set_flags_06(self):
        self._test_set_flags('/foo', 'flags=(complain,  audit)', None, whitespace='    ')
    def test_set_flags_07(self):
        self._test_set_flags('/foo', 'flags=(complain,  audit)', '', expected_flags=None)
    def test_set_flags_08(self):
        self._test_set_flags('/foo', '(  complain  )', 'audit ', whitespace='  ', profile_name=None)
    def test_set_flags_09(self):
        self._test_set_flags('profile /foo', 'flags=(complain)', 'audit')
    def test_set_flags_10(self):
        self._test_set_flags('profile xy /foo', 'flags=(complain)', 'audit', profile_name='xy')
    def test_set_flags_11(self):
        self._test_set_flags('profile "/foo bar"', 'flags=(complain)', 'audit', profile_name='/foo bar')
    def test_set_flags_12(self):
        self._test_set_flags('profile xy "/foo bar"', 'flags=(complain)', 'audit', profile_name='xy')


    # XXX regex_hat_flag in set_profile_flags() is totally broken - it matches for '   ' and '  X ', but doesn't match for ' ^foo {'
    # oh, it matches on a line like 'dbus' and changes it to 'dbus flags=(...)' if there's no leading whitespace (and no comma)
    #def test_set_flags_hat_01(self):
    #    self._test_set_flags('  ^hat', '', 'audit')


    def test_set_flags_invalid_01(self):
        with self.assertRaises(AppArmorBug):
            self._test_set_flags('/foo', '()', None, check_new_flags=False)
    def test_set_flags_invalid_02(self):
        with self.assertRaises(AppArmorBug):
            self._test_set_flags('/foo', 'flags=()', None, check_new_flags=False)
    def test_set_flags_invalid_03(self):
        with self.assertRaises(AppArmorException):
            self._test_set_flags('/foo', '(  )', '', check_new_flags=False)
    def test_set_flags_invalid_04(self):
        with self.assertRaises(AppArmorBug):
            self._test_set_flags('/foo', 'flags=(complain,  audit)', '  ', check_new_flags=False) # whitespace-only newflags

    def test_set_flags_other_profile(self):
        # test behaviour if the file doesn't contain the specified /foo profile
        orig_prof = '/no-such-profile flags=(complain) {\n}'
        self.file = write_file(self.tmpdir, 'profile', orig_prof)

        with self.assertRaises(AppArmorBug):
            set_profile_flags(self.file, '/foo', 'audit')

        # the file should not be changed
        real_new_prof = read_file(self.file)
        self.assertEqual(orig_prof, real_new_prof)

    def test_set_flags_no_profile_found(self):
        # test behaviour if the file doesn't contain any profile
        orig_prof = '# /comment flags=(complain) {\n# }'
        self.file = write_file(self.tmpdir, 'profile', orig_prof)

        with self.assertRaises(AppArmorBug):
            set_profile_flags(self.file, None, 'audit')

        # the file should not be changed
        real_new_prof = read_file(self.file)
        self.assertEqual(orig_prof, real_new_prof)

    def test_set_flags_file_not_found(self):
        with self.assertRaises(IOError):
            set_profile_flags('%s/file-not-found' % self.tmpdir, '/foo', 'audit')


class AaTest_is_skippable_file(AATest):
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

class AaTest_parse_profile_start(AATest):
    def _parse(self, line, profile, hat):
        return parse_profile_start(line, 'somefile', 1, profile, hat)
        # (profile, hat, flags, in_contained_hat, pps_set_profile, pps_set_hat_external)

    def test_parse_profile_start_01(self):
        result = self._parse('/foo {', None, None)
        expected = ('/foo', '/foo', None, None, False, False, False)
        self.assertEqual(result, expected)

    def test_parse_profile_start_02(self):
        result = self._parse('/foo (complain) {', None, None)
        expected = ('/foo', '/foo', None, 'complain', False, False, False)
        self.assertEqual(result, expected)

    def test_parse_profile_start_03(self):
        result = self._parse('profile foo /foo {', None, None) # named profile
        expected = ('foo', 'foo', '/foo', None, False, False, False)
        self.assertEqual(result, expected)

    def test_parse_profile_start_04(self):
        result = self._parse('profile /foo {', '/bar', '/bar') # child profile
        expected = ('/bar', '/foo', None, None, True, True, False)
        self.assertEqual(result, expected)

    def test_parse_profile_start_05(self):
        result = self._parse('/foo//bar {', None, None) # external hat
        expected = ('/foo', 'bar', None, None, False, False, True)
        self.assertEqual(result, expected)

    def test_parse_profile_start_06(self):
        result = self._parse('profile "/foo" (complain) {', None, None)
        expected = ('/foo', '/foo', None, 'complain', False, False, False)
        self.assertEqual(result, expected)


    def test_parse_profile_start_invalid_01(self):
        with self.assertRaises(AppArmorException):
            self._parse('/foo {', '/bar', '/bar') # child profile without profile keyword

    def test_parse_profile_start_invalid_02(self):
        with self.assertRaises(AppArmorBug):
            self._parse('xy', '/bar', '/bar') # not a profile start

class AaTest_write_header(AATest):
    tests = [
        # name       embedded_hat    write_flags    depth   flags           attachment  prof.keyw.  comment    expected
        (['/foo',    False,          True,          1,      'complain',     None,       None,       None    ],  '  /foo flags=(complain) {'),
        (['/foo',    True,           True,          1,      'complain',     None,       None,       None    ],  '  profile /foo flags=(complain) {'),
        (['/foo sp', False,          False,         2,      'complain',     None,       None,       None    ],  '    "/foo sp" {'),
        (['/foo'    ,False,          False,         2,      'complain',     None,       None,       None    ],  '    /foo {'),
        (['/foo',    True,           False,         2,      'complain',     None,       None,       None    ],  '    profile /foo {'),
        (['/foo',    False,          True,          0,      None,           None,       None,       None    ],  '/foo {'),
        (['/foo',    True,           True,          0,      None,           None,       None,       None    ],  'profile /foo {'),
        (['/foo',    False,          False,         0,      None,           None,       None,       None    ],  '/foo {'),
        (['/foo',    True,           False,         0,      None,           None,       None,       None    ],  'profile /foo {'),
        (['bar',     False,          True,          1,      'complain',     None,       None,       None    ],  '  profile bar flags=(complain) {'),
        (['bar',     False,          True,          1,      'complain',     '/foo',     None,       None    ],  '  profile bar /foo flags=(complain) {'),
        (['bar',     True,           True,          1,      'complain',     '/foo',     None,       None    ],  '  profile bar /foo flags=(complain) {'),
        (['bar baz', False,          True,          1,      None,           '/foo',     None,       None    ],  '  profile "bar baz" /foo {'),
        (['bar',     True,           True,          1,      None,           '/foo',     None,       None    ],  '  profile bar /foo {'),
        (['bar baz', False,          True,          1,      'complain',     '/foo sp',  None,       None    ],  '  profile "bar baz" "/foo sp" flags=(complain) {'),
        (['^foo',    False,          True,          1,      'complain',     None,       None,       None    ],  '  profile ^foo flags=(complain) {'),
        (['^foo',    True,           True,          1,      'complain',     None,       None,       None    ],  '  ^foo flags=(complain) {'),
        (['^foo',    True,           True,          1.5,    'complain',     None,       None,       None    ],  '   ^foo flags=(complain) {'),
        (['^foo',    True,           True,          1.3,    'complain',     None,       None,       None    ],  '  ^foo flags=(complain) {'),
        (['/foo',    False,          True,          1,      'complain',     None,       'profile',  None    ],  '  profile /foo flags=(complain) {'),
        (['/foo',    True,           True,          1,      'complain',     None,       'profile',  None    ],  '  profile /foo flags=(complain) {'),
        (['/foo',    False,          True,          1,      'complain',     None,       None,       '# x'   ],  '  /foo flags=(complain) { # x'),
        (['/foo',    True,           True,          1,      None,           None,       None,       '# x'   ],  '  profile /foo { # x'),
        (['/foo',    False,          True,          1,      None,           None,       'profile',  '# x'   ],  '  profile /foo { # x'),
        (['/foo',    True,           True,          1,      'complain',     None,       'profile',  '# x'   ],  '  profile /foo flags=(complain) { # x'),
     ]

    def _run_test(self, params, expected):
        name = params[0]
        embedded_hat = params[1]
        write_flags = params[2]
        depth = params[3]
        prof_data = { 'flags': params[4], 'attachment': params[5], 'profile_keyword': params[6], 'header_comment': params[7] }

        result = write_header(prof_data, depth, name, embedded_hat, write_flags)
        self.assertEqual(result, [expected])

class AaTest_serialize_parse_profile_start(AATest):
    def _parse(self, line, profile, hat, prof_data_profile, prof_data_external):
        # 'correct' is always True in the code that uses serialize_parse_profile_start() (set some lines above the function call)
        return serialize_parse_profile_start(line, 'somefile', 1, profile, hat, prof_data_profile, prof_data_external, True)

    def test_serialize_parse_profile_start_01(self):
        result = self._parse('/foo {', None, None, False, False)
        expected = ('/foo', '/foo', None, None, False, True)
        self.assertEqual(result, expected)

    def test_serialize_parse_profile_start_02(self):
        result = self._parse('/foo (complain) {', None, None, False, False)
        expected = ('/foo', '/foo', None, 'complain', False, True)
        self.assertEqual(result, expected)

    def test_serialize_parse_profile_start_03(self):
        result = self._parse('profile foo /foo {', None, None, False, False) # named profile
        expected = ('foo', 'foo', '/foo', None, False, True)
        self.assertEqual(result, expected)

    def test_serialize_parse_profile_start_04(self):
        result = self._parse('profile /foo {', '/bar', '/bar', False, False) # child profile
        expected = ('/bar', '/foo', None, None, True, True)
        self.assertEqual(result, expected)

    def test_serialize_parse_profile_start_05(self):
        result = self._parse('/foo//bar {', None, None, False, False) # external hat
        expected = ('/foo', 'bar', None, None, False, False) # note correct == False here
        self.assertEqual(result, expected)

    def test_serialize_parse_profile_start_06(self):
        result = self._parse('profile "/foo" (complain) {', None, None, False, False)
        expected = ('/foo', '/foo', None, 'complain', False, True)
        self.assertEqual(result, expected)

    def test_serialize_parse_profile_start_07(self):
        result = self._parse('/foo {', None, None, True, False)
        expected = ('/foo', '/foo', None, None, False, True)
        self.assertEqual(result, expected)

    def test_serialize_parse_profile_start_08(self):
        result = self._parse('/foo {', None, None, False, True)
        expected = ('/foo', '/foo', None, None, False, True)
        self.assertEqual(result, expected)

    def test_serialize_parse_profile_start_09(self):
        result = self._parse('/foo {', None, None, True, True)
        expected = ('/foo', '/foo', None, None, False, True)
        self.assertEqual(result, expected)

    def test_serialize_parse_profile_start_10(self):
        result = self._parse('profile /foo {', '/bar', '/bar', True, False) # child profile
        expected = ('/bar', '/foo', None, None, True, True)
        self.assertEqual(result, expected)

    def test_serialize_parse_profile_start_11(self):
        result = self._parse('profile /foo {', '/bar', '/bar', False, True) # child profile
        expected = ('/bar', '/foo', None, None, True, True)
        self.assertEqual(result, expected)

    def test_serialize_parse_profile_start_12(self):
        result = self._parse('profile /foo {', '/bar', '/bar', True, True) # child profile
        expected = ('/bar', '/foo', None, None, True, True)
        self.assertEqual(result, expected)

    def test_serialize_parse_profile_start_13(self):
        result = self._parse('/foo {', '/bar', '/bar', False, False) # child profile without 'profile' keyword - XXX should this error out?
        expected = ('/foo', '/foo', None, None, False, True) # note that in_contained_hat == False and that profile == hat == child profile
        self.assertEqual(result, expected)

    def test_serialize_parse_profile_start_14(self):
        result = self._parse('/ext//hat {', '/bar', '/bar', True, True) # external hat inside a profile - XXX should this error out?
        expected = ('/ext', '/ext', None, None, False, True) # XXX additionally note that hat == profile, but should be 'hat'
        self.assertEqual(result, expected)

    def test_serialize_parse_profile_start_15(self):
        result = self._parse('/ext//hat {', '/bar', '/bar', True, False) # external hat inside a profile - XXX should this error out?
        expected = ('/ext', 'hat', None, None, False, False)
        self.assertEqual(result, expected)


    def test_serialize_parse_profile_start_invalid_01(self):
        with self.assertRaises(AppArmorBug):
            self._parse('xy', '/bar', '/bar', False, False) # not a profile start

    # XXX not catched as error. See also test_serialize_parse_profile_start_13() - maybe this is wanted behaviour here?
    #def test_serialize_parse_profile_start_invalid_02(self):
    #    with self.assertRaises(AppArmorException):
    #        self._parse('/foo {', '/bar', '/bar', False, False) # child profile without profile keyword

if __name__ == '__main__':
    setup_all_tests()
    unittest.main(verbosity=2)
