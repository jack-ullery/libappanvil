#!/usr/bin/env python3
# ------------------------------------------------------------------
#
#   Copyright (C) 2013 Canonical Ltd.
#   Author: Steve Beattie <steve@nxnw.org>
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of version 2 of the GNU General Public
#   License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

# TODO
# - check cache not used if parser in $PATH is newer
# - check cache used/not used if includes are newer/older
# - check cache used for force-complain, disable symlink, etc.

from argparse import ArgumentParser
import os
import shutil
import time
import tempfile
import unittest

import testlib


PROFILE_CONTENTS = '''
# Simple example profile for caching tests

/bin/pingy {
  capability net_raw,
  capability setuid,
  network inet raw,

  /bin/ping mixr,
  /etc/modules.conf r,
}
'''
PROFILE = 'sbin.pingy'
config = None


class AAParserCachingCommon(testlib.AATestTemplate):
    do_cleanup = True

    def setUp(self):
        '''setup for each test'''
        global config

        # REPORT ALL THE OUTPUT
        self.maxDiff = None

        # skip all the things if apparmor securityfs isn't mounted
        if not os.path.exists("/sys/kernel/security/apparmor"):
            raise unittest.SkipTest("WARNING: /sys/kernel/security/apparmor does not exist. "
                                    "Skipping tests")

        self.tmp_dir = tempfile.mkdtemp(prefix='aa-caching-')
        os.chmod(self.tmp_dir, 0o755)

        # create directory for cached blobs
        self.cache_dir = os.path.join(self.tmp_dir, 'cache')
        os.mkdir(self.cache_dir)

        # write our sample profile out
        self.profile = testlib.write_file(self.tmp_dir, PROFILE, PROFILE_CONTENTS)

        if config.debug:
            self.do_cleanup = False
            self.debug = True

        self.cmd_prefix = [config.parser, '--base', self.tmp_dir, '--skip-kernel-load']

    def tearDown(self):
        '''teardown for each test'''

        if not self.do_cleanup:
            print("\n===> Skipping cleanup, leaving testfiles behind in '%s'" % (self.tmp_dir))
        else:
            if os.path.exists(self.tmp_dir):
                shutil.rmtree(self.tmp_dir)

    def assert_path_exists(self, path, expected=True):
        if expected is True:
            self.assertTrue(os.path.exists(path),
                            'test did not create file %s, when it was expected to do so' % path)
        else:
            self.assertFalse(os.path.exists(path),
                             'test created file %s, when it was not expected to do so' % path)

    def compare_features_file(self, features_path, expected=True):
        # compare features contents
        expected_output = testlib.read_features_dir('/sys/kernel/security/apparmor/features')
        with open(features_path) as f:
            features = f.read()
        if expected:
            self.assertEquals(expected_output, features,
                              "features contents differ, expected:\n%s\nresult:\n%s" % (expected_output, features))
        else:
            self.assertNotEquals(expected_output, features,
                                 "features contents equal, expected:\n%s\nresult:\n%s" % (expected_output, features))


class AAParserBasicCachingTests(AAParserCachingCommon):

    def setUp(self):
        super(AAParserBasicCachingTests, self).setUp()

    def test_no_cache_by_default(self):
        '''test profiles are not cached by default'''

        cmd = list(self.cmd_prefix)
        cmd.extend(['-q', '-r', self.profile])
        self.run_cmd_check(cmd)
        self.assert_path_exists(os.path.join(self.cache_dir, PROFILE), expected=False)

    def test_no_cache_w_skip_cache(self):
        '''test profiles are not cached with --skip-cache'''

        cmd = list(self.cmd_prefix)
        cmd.extend(['-q', '--write-cache', '--skip-cache', '-r', self.profile])
        self.run_cmd_check(cmd)
        self.assert_path_exists(os.path.join(self.cache_dir, PROFILE), expected=False)

    def test_cache_when_requested(self):
        '''test profiles are cached when requested'''

        cmd = list(self.cmd_prefix)
        cmd.extend(['-q', '--write-cache', '-r', self.profile])
        self.run_cmd_check(cmd)
        self.assert_path_exists(os.path.join(self.cache_dir, PROFILE))

    def test_write_features_when_caching(self):
        '''test features file is written when caching'''

        cmd = list(self.cmd_prefix)
        cmd.extend(['-q', '--write-cache', '-r', self.profile])
        self.run_cmd_check(cmd)
        self.assert_path_exists(os.path.join(self.cache_dir, PROFILE))
        self.assert_path_exists(os.path.join(self.cache_dir, '.features'))

    def test_features_match_when_caching(self):
        '''test features file is written when caching'''

        cmd = list(self.cmd_prefix)
        cmd.extend(['-q', '--write-cache', '-r', self.profile])
        self.run_cmd_check(cmd)
        self.assert_path_exists(os.path.join(self.cache_dir, PROFILE))
        self.assert_path_exists(os.path.join(self.cache_dir, '.features'))

        self.compare_features_file(os.path.join(self.cache_dir, '.features'))


class AAParserAltCacheBasicTests(AAParserBasicCachingTests):
    '''Same tests as above, but with an alternate cache location specified on the command line'''

    def setUp(self):
        super(AAParserAltCacheBasicTests, self).setUp()

        alt_cache_dir = tempfile.mkdtemp(prefix='aa-alt-cache', dir=self.tmp_dir)
        os.chmod(alt_cache_dir, 0o755)

        self.unused_cache_dir = self.cache_dir
        self.cache_dir = alt_cache_dir
        self.cmd_prefix.extend(['--cache-loc', alt_cache_dir])

    def tearDown(self):
        if len(os.listdir(self.unused_cache_dir)) > 0:
            self.fail('original cache dir \'%s\' not empty' % self.unused_cache_dir)
        super(AAParserAltCacheBasicTests, self).tearDown()


class AAParserCreateCacheBasicTestsCacheExists(AAParserBasicCachingTests):
    '''Same tests as above, but with create cache option on the command line and the cache already exists'''

    def setUp(self):
        super(AAParserCreateCacheBasicTestsCacheExists, self).setUp()
        self.cmd_prefix.append('--create-cache-dir')


class AAParserCreateCacheBasicTestsCacheNotExist(AAParserBasicCachingTests):
    '''Same tests as above, but with create cache option on the command line and cache dir removed'''

    def setUp(self):
        super(AAParserCreateCacheBasicTestsCacheNotExist, self).setUp()
        shutil.rmtree(self.cache_dir)
        self.cmd_prefix.append('--create-cache-dir')


class AAParserCreateCacheAltCacheTestsCacheNotExist(AAParserBasicCachingTests):
    '''Same tests as above, but with create cache option on the command line,
       alt cache specified, and cache dir removed'''

    def setUp(self):
        super(AAParserCreateCacheAltCacheTestsCacheNotExist, self).setUp()
        shutil.rmtree(self.cache_dir)
        self.cmd_prefix.append('--create-cache-dir')


class AAParserCachingTests(AAParserCachingCommon):

    def setUp(self):
        super(AAParserCachingTests, self).setUp()

        # need separation of length timeout between generating profile
        # and generating cache entry, as the parser distinguishes
        # between ctime, not mtime.
        if not 'timeout' in dir(config):
            r = testlib.filesystem_time_resolution()
            config.timeout = r[1]

        time.sleep(config.timeout)

    def _generate_cache_file(self):

        cmd = list(self.cmd_prefix)
        cmd.extend(['-q', '--write-cache', '-r', self.profile])
        self.run_cmd_check(cmd)
        self.assert_path_exists(os.path.join(self.cache_dir, PROFILE))

    def test_cache_loaded_when_exists(self):
        '''test cache is loaded when it exists, is newer than profile,  and features match'''

        self._generate_cache_file()

        cmd = list(self.cmd_prefix)
        cmd.extend(['-v', '-r', self.profile])
        self.run_cmd_check(cmd, expected_string='Cached reload succeeded')

    def test_cache_not_loaded_when_skip_arg(self):
        '''test cache is not loaded when --skip-cache is passed'''

        self._generate_cache_file()

        cmd = list(self.cmd_prefix)
        cmd.extend(['-v', '--skip-cache', '-r', self.profile])
        self.run_cmd_check(cmd, expected_string='Replacement succeeded for')

    def test_cache_not_loaded_when_skip_read_arg(self):
        '''test cache is not loaded when --skip-read-cache is passed'''

        self._generate_cache_file()

        cmd = list(self.cmd_prefix)
        cmd.extend(['-v', '--skip-read-cache', '-r', self.profile])
        self.run_cmd_check(cmd, expected_string='Replacement succeeded for')

    def test_cache_not_loaded_when_features_differ(self):
        '''test cache is not loaded when features file differs'''

        self._generate_cache_file()

        testlib.write_file(self.cache_dir, '.features', 'monkey\n')

        cmd = list(self.cmd_prefix)
        cmd.extend(['-v', '-r', self.profile])
        self.run_cmd_check(cmd, expected_string='Replacement succeeded for')

    def test_cache_writing_does_not_overwrite_features_when_features_differ(self):
        '''test cache writing does not overwrite the features files when it differs and --skip-bad-cache is given'''

        features_file = testlib.write_file(self.cache_dir, '.features', 'monkey\n')

        cmd = list(self.cmd_prefix)
        cmd.extend(['-v', '--write-cache', '--skip-bad-cache', '-r', self.profile])
        self.run_cmd_check(cmd, expected_string='Replacement succeeded for')
        self.assert_path_exists(features_file)
        # ensure that the features does *not* match the current features set
        self.compare_features_file(features_file, expected=False)

    def test_cache_writing_skipped_when_features_differ(self):
        '''test cache writing is skipped when features file differs'''

        testlib.write_file(self.cache_dir, '.features', 'monkey\n')

        cmd = list(self.cmd_prefix)
        cmd.extend(['-v', '--write-cache', '--skip-bad-cache', '-r', self.profile])
        self.run_cmd_check(cmd, expected_string='Replacement succeeded for')
        self.assert_path_exists(os.path.join(self.cache_dir, PROFILE), expected=False)

    def test_cache_writing_updates_features(self):
        '''test cache writing updates features'''

        features_file = testlib.write_file(self.cache_dir, '.features', 'monkey\n')

        cmd = list(self.cmd_prefix)
        cmd.extend(['-v', '--write-cache', '-r', self.profile])
        self.run_cmd_check(cmd, expected_string='Replacement succeeded for')
        self.assert_path_exists(features_file)
        self.compare_features_file(features_file)

    def test_cache_writing_updates_cache_file(self):
        '''test cache writing updates cache file'''

        cache_file = testlib.write_file(self.cache_dir, PROFILE, 'monkey\n')
        orig_size = os.stat(cache_file).st_size

        cmd = list(self.cmd_prefix)
        cmd.extend(['-v', '--write-cache', '-r', self.profile])
        self.run_cmd_check(cmd, expected_string='Replacement succeeded for')
        self.assert_path_exists(cache_file)
        with open(cache_file, 'rb') as f:
            new_size = os.fstat(f.fileno()).st_size
        # We check sizes here rather than whether the string monkey is
        # in cache_contents because of the difficulty coercing cache
        # file bytes into strings in python3
        self.assertNotEquals(orig_size, new_size, 'Expected cache file to be updated, size is not changed.')

    def test_cache_writing_clears_all_files(self):
        '''test cache writing clears all cache files'''

        check_file = testlib.write_file(self.cache_dir, 'monkey', 'monkey\n')

        cmd = list(self.cmd_prefix)
        cmd.extend(['-v', '--write-cache', '-r', self.profile])
        self.run_cmd_check(cmd, expected_string='Replacement succeeded for')
        self.assert_path_exists(check_file, expected=False)

    def test_profile_newer_skips_cache(self):
        '''test cache is skipped if profile is newer'''

        self._generate_cache_file()
        time.sleep(config.timeout)
        testlib.touch(self.profile)

        cmd = list(self.cmd_prefix)
        cmd.extend(['-v', '-r', self.profile])
        self.run_cmd_check(cmd, expected_string='Replacement succeeded for')

    def test_parser_newer_uses_cache(self):
        '''test cache is not skipped if parser is newer'''

        self._generate_cache_file()
        time.sleep(config.timeout)

        # copy parser
        os.mkdir(os.path.join(self.tmp_dir, 'parser'))
        new_parser = os.path.join(self.tmp_dir, 'parser', 'apparmor_parser')
        shutil.copy(config.parser, new_parser)

        cmd = list(self.cmd_prefix)
        cmd[0] = new_parser
        cmd.extend(['-v', '-r', self.profile])
        self.run_cmd_check(cmd, expected_string='Cached reload succeeded for')

    def _purge_cache_test(self, location):

        cache_file = testlib.write_file(self.cache_dir, location, 'monkey\n')

        cmd = list(self.cmd_prefix)
        cmd.extend(['-v', '--purge-cache', '-r', self.profile])
        self.run_cmd_check(cmd)
        # no message is output
        self.assert_path_exists(cache_file, expected=False)

    def test_cache_purge_removes_features_file(self):
        '''test cache --purge-cache removes .features file'''
        self._purge_cache_test('.features')

    def test_cache_purge_removes_cache_file(self):
        '''test cache --purge-cache removes profile cache file'''
        self._purge_cache_test(PROFILE)

    def test_cache_purge_removes_other_cache_files(self):
        '''test cache --purge-cache removes other cache files'''
        self._purge_cache_test('monkey')


class AAParserAltCacheTests(AAParserCachingTests):
    '''Same tests as above, but with an alternate cache location specified on the command line'''
    check_orig_cache = True

    def setUp(self):
        super(AAParserAltCacheTests, self).setUp()

        alt_cache_dir = tempfile.mkdtemp(prefix='aa-alt-cache', dir=self.tmp_dir)
        os.chmod(alt_cache_dir, 0o755)

        self.orig_cache_dir = self.cache_dir
        self.cache_dir = alt_cache_dir
        self.cmd_prefix.extend(['--cache-loc', alt_cache_dir])

    def tearDown(self):
        if self.check_orig_cache and len(os.listdir(self.orig_cache_dir)) > 0:
            self.fail('original cache dir \'%s\' not empty' % self.orig_cache_dir)
        super(AAParserAltCacheTests, self).tearDown()

    def test_cache_purge_leaves_original_cache_alone(self):
        '''test cache purging only touches alt cache'''

        # skip tearDown check to ensure non-alt cache is empty
        self.check_orig_cache = False
        filelist = [PROFILE, '.features', 'monkey']

        for f in filelist:
            testlib.write_file(self.orig_cache_dir, f, 'monkey\n')

        self._purge_cache_test(PROFILE)

        for f in filelist:
            if not os.path.exists(os.path.join(self.orig_cache_dir, f)):
                self.fail('cache purge removed %s, was not supposed to' % (os.path.join(self.orig_cache_dir, f)))


def main():
    global config
    p = ArgumentParser()
    p.add_argument('-p', '--parser', default=testlib.DEFAULT_PARSER, action="store", dest='parser')
    p.add_argument('-v', '--verbose', action="store_true", dest="verbose")
    p.add_argument('-d', '--debug', action="store_true", dest="debug")
    config = p.parse_args()

    verbosity = 1
    if config.verbose:
        verbosity = 2

    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AAParserBasicCachingTests))
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AAParserAltCacheBasicTests))
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AAParserCreateCacheBasicTestsCacheExists))
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AAParserCreateCacheBasicTestsCacheNotExist))
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AAParserCreateCacheAltCacheTestsCacheNotExist))
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AAParserCachingTests))
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AAParserAltCacheTests))
    rc = 0
    try:
        result = unittest.TextTestRunner(verbosity=verbosity).run(test_suite)
        if not result.wasSuccessful():
            rc = 1
    except:
        rc = 1

    return rc

if __name__ == "__main__":
    rc = main()
    exit(rc)
