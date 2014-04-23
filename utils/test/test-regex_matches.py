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


class AARegexHasComma(unittest.TestCase):
    '''Tests for apparmor.aa.RE_RULE_HAS_COMMA'''

    def _check(self, line, expected=True):
        result = aa.RE_RULE_HAS_COMMA.search(line)
        if expected:
            self.assertTrue(result, 'Couldn\'t find a comma in "%s"' % line)
        else:
            self.assertEqual(None, result, 'Found an unexpected comma in "%s"' % line)

regex_has_comma_testcases = [
    ('dbus send%s', 'simple'),
    ('dbus (r, w, bind, eavesdrop)%s', 'embedded parens 01'),
    ('dbus (r, w,, bind, eavesdrop) %s', 'embedded parens 02'),
    ('dbus (r, w,, ) %s', 'embedded parens 03'),
    ('dbus () %s', 'empty parens'),
    ('member={Hello,AddMatch,RemoveMatch,GetNameOwner,NameHasOwner,StartServiceByName} %s ', 'embedded curly braces 01'),
    ('member={Hello,,,,,,AddMatch,,,NameHasOwner,StartServiceByName} %s ', 'embedded curly braces 02'),
    ('member={,Hello,,,,,,AddMatch,,,NameHasOwner,} %s ', 'embedded curly braces 03'),
    ('member={} %s ', 'empty curly braces'),
    ('dbus send%s# this is a comment', 'comment 01'),
    ('dbus send%s# this is a comment,', 'comment 02'),
    ('audit "/tmp/foo, bar" rw%s', 'quotes 01'),
    ('audit "/tmp/foo, bar" rw%s # comment', 'quotes 02'),
    ('audit "/tmp/foo, # bar" rw%s', 'comment embedded in quote 01'),
    ('audit "/tmp/foo, # bar" rw%s # comment', 'comment embedded in quote 02'),

    # lifted from parser/tst/simple_tests/vars/vars_alternation_3.sd
    ('/does/not/@{BAR},exist,notexist} r%s', 'partial alternation'),

    ('signal%s', 'bare signal'),
    ('signal receive%s', 'simple signal'),
    ('signal (send, receive)%s', 'embedded parens signal 01'),
    ('signal (send, receive) set=(hup, quit)%s', 'embedded parens signal 02'),

    ('ptrace%s', 'bare ptrace'),
    ('ptrace trace%s', 'simple ptrace'),
    ('ptrace (tracedby, readby)%s', 'embedded parens ptrace 01'),
    ('ptrace (trace) peer=/usr/bin/foo%s', 'embedded parens ptrace 02'),

    # the following fail due to inadequacies in the regex
    # ('dbus (r, w, %s', 'incomplete dbus action'),
    # ('member="{Hello,AddMatch,RemoveMatch, %s', 'incomplete {} regex'),  # also invalid policy
    # ('member={Hello,AddMatch,RemoveMatch, %s', 'incomplete {} regex'),  # also invalid policy when trailing comma exists

    # the following passes the tests, but variable declarations are
    # odd in that they *don't* allow trailing commas; commas at the end
    # of the line need to be quoted.
    # ('@{BAR}={bar,baz,blort %s', 'tricksy variable declaration')
    # ('@{BAR}="{bar,baz,blort," %s', 'tricksy variable declaration')
    # The following fails the no comma test, but is invalid
    # ('@{BAR}={bar,baz,blort, %s', 'tricksy variable declaration')
    # The following fails the comma test, because it's really a no comma situation
    # ('@{BAR}="{bar,baz,blort%s" ', 'tricksy variable declaration')
]

def setup_has_comma_testcases():
    i = 0
    for (test_string, description) in regex_has_comma_testcases:
        i += 1
        def stub_test_comma(self, test_string=test_string):
            self._check(test_string % ',')
        def stub_test_no_comma(self, test_string=test_string):
            self._check(test_string % ' ', False)
        stub_test_comma.__doc__ = "test %s (w/comma)" % (description)
        stub_test_no_comma.__doc__ = "test %s (no comma)" % (description)
        setattr(AARegexHasComma, 'test_comma_%d' % (i), stub_test_comma)
        setattr(AARegexHasComma, 'test_no_comma_%d' % (i), stub_test_no_comma)

class AARegexSplitComment(unittest.TestCase):
    '''Tests for RE_HAS_COMMENT_SPLIT'''

    def _check(self, line, expected, comment=None, not_comment=None):
        result = aa.RE_HAS_COMMENT_SPLIT.search(line)
        if expected:
            self.assertTrue(result, 'Couldn\'t find a comment in "%s"' % line)
            self.assertEqual(result.group('comment'), comment, 'Expected comment "%s", got "%s"'
                             % (comment, result.group('comment')))
            self.assertEqual(result.group('not_comment'), not_comment, 'Expected not comment "%s", got "%s"'
                             % (not_comment, result.group('not_comment')))
        else:
            self.assertEqual(None, result, 'Found an unexpected comment "%s" in "%s"'
                             % ("" if result is None else result.group('comment'), line ))

# Tuples of (string, expected result), where expected result is False if
# the string should not be considered as having a comment, or a second
# tuple of the not comment and comment sections split apart
regex_split_comment_testcases = [
    ('dbus send # this is a comment', ('dbus send ', '# this is a comment')),
    ('dbus send member=no_comment', False),
    ('dbus send member=no_comment, ', False),
    ('audit "/tmp/foo, # bar" rw', False),
    ('audit "/tmp/foo, # bar" rw # comment', ('audit "/tmp/foo, # bar" rw ', '# comment')),
    ('file,', False),
    ('file, # bare', ('file, ', '# bare')),
    ('file /tmp/foo rw, # read-write', ('file /tmp/foo rw, ', '# read-write')),
    ('signal, # comment', ('signal, ', '# comment')),
    ('signal receive set=(usr1 usr2) peer=foo,', False),
    ('ptrace, # comment', ('ptrace, ', '# comment')),
    ('ptrace (trace read) peer=/usr/bin/foo,', False),
]

def setup_split_comment_testcases():
    i = 0
    for (test_string, result) in regex_split_comment_testcases:
        i += 1
        def stub_test(self, test_string=test_string, result=result):
            if result is False:
                self._check(test_string, False)
            else:
                self._check(test_string, True, not_comment=result[0], comment=result[1])
        stub_test.__doc__ = "test '%s'" % (test_string)
        setattr(AARegexSplitComment, 'test_split_comment_%d' % (i), stub_test)

class AARegexCapability(unittest.TestCase):
    '''Tests for RE_PROFILE_CAP'''

    def test_simple_capability_01(self):
        '''test '   capability net_raw,' '''

        line = '   capability net_raw,'
        result = aa.RE_PROFILE_CAP.search(line)
        self.assertTrue(result, 'Couldn\'t find capability rule in "%s"' % line)
        cap = result.groups()[2].strip()
        self.assertEqual(cap, 'net_raw', 'Expected capability "%s", got "%s"'
                         % ('net_raw', cap))

    def test_simple_capability_02(self):
        '''test '   capability net_raw   ,  ' '''

        line = 'capability     net_raw   ,  '
        result = aa.RE_PROFILE_CAP.search(line)
        self.assertTrue(result, 'Couldn\'t find capability rule in "%s"' % line)
        cap = result.groups()[2].strip()
        self.assertEqual(cap, 'net_raw', 'Expected capability "%s", got "%s"'
                         % ('net_raw', cap))

    def test_capability_all_01(self):
        '''test '   capability,' '''

        line = '   capability,'
        result = aa.RE_PROFILE_CAP.search(line)
        self.assertTrue(result, 'Couldn\'t find capability rule in "%s"' % line)

    def test_capability_all_02(self):
        '''test '   capability   ,  ' '''

        line = '   capability   ,  '
        result = aa.RE_PROFILE_CAP.search(line)
        self.assertTrue(result, 'Couldn\'t find capability rule in "%s"' % line)

    def test_simple_bad_capability_01(self):
        '''test '   capabilitynet_raw,' '''

        line = '   capabilitynet_raw,'
        result = aa.RE_PROFILE_CAP.search(line)
        self.assertFalse(result, 'Found unexpected capability rule in "%s"' % line)

class AARegexPath(unittest.TestCase):
    '''Tests for RE_PROFILE_PATH_ENTRY'''

    def test_simple_path_01(self):
        '''test '   /tmp/foo r,' '''

        line = '   /tmp/foo r,'
        result = aa.RE_PROFILE_PATH_ENTRY.search(line)
        self.assertTrue(result, 'Couldn\'t find file rule in "%s"' % line)
        mode = result.groups()[4].strip()
        self.assertEqual(mode, 'r', 'Expected mode "r", got "%s"' % (mode))

    def test_simple_path_02(self):
        '''test '   audit /tmp/foo rw,' '''

        line = '   audit /tmp/foo rw,'
        result = aa.RE_PROFILE_PATH_ENTRY.search(line)
        self.assertTrue(result, 'Couldn\'t find file rule in "%s"' % line)
        audit = result.groups()[0].strip()
        self.assertEqual(audit, 'audit', 'Couldn\t find audit modifier')
        mode = result.groups()[4].strip()
        self.assertEqual(mode, 'rw', 'Expected mode "rw", got "%s"' % (mode))

    def test_simple_path_03(self):
        '''test '   audit deny /tmp/foo rw,' '''

        line = '   audit deny /tmp/foo rw,'
        result = aa.RE_PROFILE_PATH_ENTRY.search(line)
        self.assertTrue(result, 'Couldn\'t find file rule in "%s"' % line)
        audit = result.groups()[0].strip()
        self.assertEqual(audit, 'audit', 'Couldn\t find audit modifier')
        deny = result.groups()[1].strip()
        self.assertEqual(deny, 'deny', 'Couldn\t find deny modifier')
        mode = result.groups()[4].strip()
        self.assertEqual(mode, 'rw', 'Expected mode "rw", got "%s"' % (mode))

    def test_simple_bad_path_01(self):
        '''test '   file,' '''

        line = '   file,'
        result = aa.RE_PROFILE_PATH_ENTRY.search(line)
        self.assertFalse(result, 'RE_PROFILE_PATH_ENTRY unexpectedly matched "%s"' % line)

    def test_simple_bad_path_02(self):
        '''test '   file /tmp/foo rw,' '''

        line = '   file /tmp/foo rw,'
        result = aa.RE_PROFILE_PATH_ENTRY.search(line)
        self.assertFalse(result, 'RE_PROFILE_PATH_ENTRY unexpectedly matched "%s"' % line)

class AARegexFile(unittest.TestCase):
    '''Tests for RE_PROFILE_FILE_ENTRY'''

    def _assertEqualStrings(self, str1, str2):
        self.assertEqual(str1, str2, 'Expected %s, got "%s"' % (str1, str2))

    def test_simple_file_01(self):
        '''test '   file /tmp/foo rw,' '''

        path = '/tmp/foo'
        mode = 'rw'
        line = '   file %s %s,' % (path, mode)
        result = aa.RE_PROFILE_FILE_ENTRY.search(line)
        self.assertTrue(result, 'Couldn\'t find file rule in "%s"' % line)
        self._assertEqualStrings(path, result.groups()[3].strip())
        self._assertEqualStrings(mode, result.groups()[4].strip())

    def test_simple_file_02(self):
        '''test '   file,' '''

        line = '   file,'
        result = aa.RE_PROFILE_FILE_ENTRY.search(line)
        self.assertTrue(result, 'Couldn\'t find file rule in "%s"' % line)
        path = result.groups()[3]
        self.assertEqual(path, None, 'Unexpected path, got "%s"' % path)
        mode = result.groups()[4]
        self.assertEqual(mode, None, 'Unexpected mode, got "%s"' % (mode))

    def test_simple_file_03(self):
        '''test '   audit file,' '''

        line = '   audit file,'
        result = aa.RE_PROFILE_FILE_ENTRY.search(line)
        self.assertTrue(result, 'Couldn\'t find file rule in "%s"' % line)
        audit = result.groups()[0].strip()
        self.assertEqual(audit, 'audit', 'Couldn\t find audit modifier')
        path = result.groups()[3]
        self.assertEqual(path, None, 'Unexpected path, got "%s"' % path)
        mode = result.groups()[4]
        self.assertEqual(mode, None, 'Unexpected mode, got "%s"' % (mode))

    def test_simple_bad_file_01(self):
        '''test '   dbus,' '''

        line = '   dbus,'
        result = aa.RE_PROFILE_FILE_ENTRY.search(line)
        self.assertFalse(result, 'RE_PROFILE_FILE_ENTRY unexpectedly matched "%s"' % line)

    def test_simple_bad_file_02(self):
        '''test '   /tmp/foo rw,' '''

        line = '   /tmp/foo rw,'
        result = aa.RE_PROFILE_FILE_ENTRY.search(line)
        self.assertFalse(result, 'RE_PROFILE_FILE_ENTRY unexpectedly matched "%s"' % line)

    def test_simple_bad_file_03(self):
        '''test '   file /tmp/foo,' '''

        line = '   file /tmp/foo,'
        result = aa.RE_PROFILE_FILE_ENTRY.search(line)
        self.assertFalse(result, 'RE_PROFILE_FILE_ENTRY unexpectedly matched "%s"' % line)

    def test_simple_bad_file_04(self):
        '''test '   file r,' '''

        line = '   file r,'
        result = aa.RE_PROFILE_FILE_ENTRY.search(line)
        self.assertFalse(result, 'RE_PROFILE_FILE_ENTRY unexpectedly matched "%s"' % line)

class AARegexSignal(unittest.TestCase):
    '''Tests for RE_PROFILE_SIGNAL'''

    def test_bare_signal_01(self):
        '''test '   signal,' '''

        rule = 'signal,'
        line = '   %s' % rule
        result = aa.RE_PROFILE_SIGNAL.search(line)
        self.assertTrue(result, 'Couldn\'t find signal rule in "%s"' % line)
        parsed = result.groups()[2].strip()
        self.assertEqual(parsed, rule, 'Expected signal rule "%s", got "%s"'
                         % (rule, parsed))

    def test_bare_signal_02(self):
        '''test '   audit signal,' '''

        rule = 'signal,'
        line = '   audit %s' % rule
        result = aa.RE_PROFILE_SIGNAL.search(line)
        self.assertTrue(result, 'Couldn\'t find signal rule in "%s"' % line)
        self.assertTrue(result.groups()[0], 'Couldn\'t find audit modifier in "%s"' % line)
        parsed = result.groups()[2].strip()
        self.assertEqual(parsed, rule, 'Expected signal rule "%s", got "%s"'
                         % (rule, parsed))

    def test_simple_signal_01(self):
        '''test '   signal receive,' '''

        rule = 'signal receive,'
        line = '   %s' % rule
        result = aa.RE_PROFILE_SIGNAL.search(line)
        self.assertTrue(result, 'Couldn\'t find signal rule in "%s"' % line)
        parsed = result.groups()[2].strip()
        self.assertEqual(parsed, rule, 'Expected signal rule "%s", got "%s"'
                         % (rule, parsed))

    def test_simple_signal_02(self):
        '''test '   signal (send, receive),' '''

        rule = 'signal (send, receive),'
        line = '   %s' % rule
        result = aa.RE_PROFILE_SIGNAL.search(line)
        self.assertTrue(result, 'Couldn\'t find signal rule in "%s"' % line)
        parsed = result.groups()[2].strip()
        self.assertEqual(parsed, rule, 'Expected signal rule "%s", got "%s"'
                         % (rule, parsed))

    def test_simple_signal_03(self):
        '''test '   audit signal (receive),' '''

        rule = 'signal (receive),'
        line = '   audit %s' % rule
        result = aa.RE_PROFILE_SIGNAL.search(line)
        self.assertTrue(result, 'Couldn\'t find signal rule in "%s"' % line)
        self.assertTrue(result.groups()[0], 'Couldn\'t find audit modifier in "%s"' % line)
        parsed = result.groups()[2].strip()
        self.assertEqual(parsed, rule, 'Expected signal rule "%s", got "%s"'
                         % (rule, parsed))

    def test_set_signal_01(self):
        '''test '   signal (send, receive) set=(usr1 usr2),' '''

        rule = 'signal (send, receive) set=(usr1 usr2),'
        line = '   %s' % rule
        result = aa.RE_PROFILE_SIGNAL.search(line)
        self.assertTrue(result, 'Couldn\'t find signal rule in "%s"' % line)
        parsed = result.groups()[2].strip()
        self.assertEqual(parsed, rule, 'Expected signal rule "%s", got "%s"'
                         % (rule, parsed))

    def test_peer_signal_01(self):
        '''test '   signal send set=(hup, quit) peer=/usr/sbin/daemon,' '''

        rule = 'signal send set=(hup, quit) peer=/usr/sbin/daemon,'
        line = '   %s' % rule
        result = aa.RE_PROFILE_SIGNAL.search(line)
        self.assertTrue(result, 'Couldn\'t find signal rule in "%s"' % line)
        parsed = result.groups()[2].strip()
        self.assertEqual(parsed, rule, 'Expected signal rule "%s", got "%s"'
                         % (rule, parsed))

class AARegexPtrace(unittest.TestCase):
    '''Tests for RE_PROFILE_PTRACE'''

    def test_bare_ptrace_01(self):
        '''test '   ptrace,' '''

        rule = 'ptrace,'
        line = '   %s' % rule
        result = aa.RE_PROFILE_PTRACE.search(line)
        self.assertTrue(result, 'Couldn\'t find ptrace rule in "%s"' % line)
        parsed = result.groups()[2].strip()
        self.assertEqual(parsed, rule, 'Expected ptrace rule "%s", got "%s"'
                         % (rule, parsed))

    def test_bare_ptrace_02(self):
        '''test '   audit ptrace,' '''

        rule = 'ptrace,'
        line = '   audit %s' % rule
        result = aa.RE_PROFILE_PTRACE.search(line)
        self.assertTrue(result, 'Couldn\'t find ptrace rule in "%s"' % line)
        self.assertTrue(result.groups()[0], 'Couldn\'t find audit modifier in "%s"' % line)
        parsed = result.groups()[2].strip()
        self.assertEqual(parsed, rule, 'Expected ptrace rule "%s", got "%s"'
                         % (rule, parsed))

    def test_simple_ptrace_01(self):
        '''test '   ptrace trace,' '''

        rule = 'ptrace trace,'
        line = '   %s' % rule
        result = aa.RE_PROFILE_PTRACE.search(line)
        self.assertTrue(result, 'Couldn\'t find ptrace rule in "%s"' % line)
        parsed = result.groups()[2].strip()
        self.assertEqual(parsed, rule, 'Expected ptrace rule "%s", got "%s"'
                         % (rule, parsed))

    def test_simple_ptrace_02(self):
        '''test '   ptrace (tracedby, readby),' '''

        rule = 'ptrace (tracedby, readby),'
        line = '   %s' % rule
        result = aa.RE_PROFILE_PTRACE.search(line)
        self.assertTrue(result, 'Couldn\'t find ptrace rule in "%s"' % line)
        parsed = result.groups()[2].strip()
        self.assertEqual(parsed, rule, 'Expected ptrace rule "%s", got "%s"'
                         % (rule, parsed))

    def test_simple_ptrace_03(self):
        '''test '   audit ptrace (read),' '''

        rule = 'ptrace (read),'
        line = '   audit %s' % rule
        result = aa.RE_PROFILE_PTRACE.search(line)
        self.assertTrue(result, 'Couldn\'t find ptrace rule in "%s"' % line)
        self.assertTrue(result.groups()[0], 'Couldn\'t find audit modifier in "%s"' % line)
        parsed = result.groups()[2].strip()
        self.assertEqual(parsed, rule, 'Expected ptrace rule "%s", got "%s"'
                         % (rule, parsed))

    def test_peer_ptrace_01(self):
        '''test '   ptrace trace peer=/usr/sbin/daemon,' '''

        rule = 'ptrace trace peer=/usr/sbin/daemon,'
        line = '   %s' % rule
        result = aa.RE_PROFILE_PTRACE.search(line)
        self.assertTrue(result, 'Couldn\'t find ptrace rule in "%s"' % line)
        parsed = result.groups()[2].strip()
        self.assertEqual(parsed, rule, 'Expected ptrace rule "%s", got "%s"'
                         % (rule, parsed))

if __name__ == '__main__':
    verbosity = 2

    setup_has_comma_testcases()
    setup_split_comment_testcases()

    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AARegexHasComma))
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AARegexSplitComment))
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AARegexCapability))
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AARegexPath))
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AARegexFile))
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AARegexSignal))
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AARegexPtrace))
    result = unittest.TextTestRunner(verbosity=verbosity).run(test_suite)
    if not result.wasSuccessful():
        exit(1)
