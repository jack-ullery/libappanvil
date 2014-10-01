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

    ('pivot_root%s', 'bare pivot_root'),
    ('pivot_root /old%s', 'pivot_root with old'),
    ('pivot_root /old new%s', 'pivot_root with new'),
    ('pivot_root /old /new -> child%s', 'pivot_root with child'),

    ('unix%s', 'bare unix'),
    ('unix create%s', 'simple unix'),
    ('peer=(addr=@abad1dea,label=a_profile) %s ', 'peer parens and comma'),
    ('type=stream%s', 'unix type'),
    ('unix (connect, receive, send)%s', 'unix perms'),

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
    ('pivot_root, # comment', ('pivot_root, ', '# comment')),
    ('pivot_root /old /new -> child,', False),
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


def regex_test(self, line, expected):
    '''Run a line through self.regex.search() and verify the result

    Keyword arguments:
    line -- the line to search
    expected -- False if the search isn't expected to match or, if the search
                is expected to match, a tuple of expected match groups with all
                of the strings stripped
    '''
    result = self.regex.search(line)
    if not expected:
        self.assertFalse(result)
        return

    self.assertTrue(result)

    groups = result.groups()
    self.assertEqual(len(groups), len(expected))
    for (i, group) in enumerate(groups):
        if group:
            group = group.strip()
        self.assertEqual(group, expected[i], 'Group %d mismatch in rule %s' % (i,line))


def setup_regex_tests(test_class):
    '''Create tests in test_class using test_class.tests and regex_tests()

    test_class.tests should be tuples of (line, expected_results) where
    expected_results is False if test_class.regex.search(line) should not
    match. If the search should match, expected_results should be a tuple of
    the expected groups, with all of the strings stripped.
    '''
    for (i, (line, expected)) in enumerate(test_class.tests):
        def stub_test(self, line=line, expected=expected):
            regex_test(self, line, expected)

        stub_test.__doc__ = "test '%s'" % (line)
        setattr(test_class, 'test_%d' % (i), stub_test)


class AARegexCapability(unittest.TestCase):
    '''Tests for RE_PROFILE_CAP'''

    def setUp(self):
        self.regex = aa.RE_PROFILE_CAP

    tests = [
        ('   capability net_raw,', (None, None, 'net_raw', 'net_raw', None)),
        ('capability     net_raw   ,  ', (None, None, 'net_raw', 'net_raw', None)),
        ('   capability,', (None, None, None, None, None)),
        ('   capability   ,  ', (None, None, None, None, None)),
        ('   capabilitynet_raw,', False)
    ]


class AARegexPath(unittest.TestCase):
    '''Tests for RE_PROFILE_PATH_ENTRY'''

    def setUp(self):
        self.regex = aa.RE_PROFILE_PATH_ENTRY

    tests = [
        ('   /tmp/foo r,',
         (None, None, None, None, '/tmp/foo', 'r', None, None, None)),
        ('   audit /tmp/foo rw,',
         ('audit', None, None, None, '/tmp/foo', 'rw', None, None, None)),
        ('   audit deny /tmp/foo rw,',
         ('audit', 'deny', None, None, '/tmp/foo', 'rw', None, None, None)),
        ('   file /tmp/foo rw,',
         (None, None, None, 'file', '/tmp/foo', 'rw', None, None, None)),
        ('   file,', False),
    ]


class AARegexBareFile(unittest.TestCase):
    '''Tests for RE_PROFILE_BARE_FILE_ENTRY'''

    def setUp(self):
        self.regex = aa.RE_PROFILE_BARE_FILE_ENTRY

    tests = [
        ('   file,', (None, None, None, None)),
        ('   dbus,', False),
        ('   file /tmp/foo rw,', False),
        ('   file /tmp/foo,', False),
        ('   file r,', False),
        ('  owner file  , ', (None, None, 'owner', None)),
        ('  audit owner file  , ', ('audit', None, 'owner', None)),
        ('  deny file  , ', (None, 'deny', None, None)),
    ]


class AARegexDbus(unittest.TestCase):
    '''Tests for RE_PROFILE_DBUS'''

    def setUp(self):
        self.regex = aa.RE_PROFILE_DBUS

    tests = [
        ('   dbus,', (None, None, 'dbus,', None)),
        ('   audit dbus,', ('audit', None, 'dbus,', None)),
        ('   dbus send member=no_comment,', (None, None, 'dbus send member=no_comment,', None)),
        ('   dbus send member=no_comment, # comment', (None, None, 'dbus send member=no_comment,', '# comment')),

        ('   dbusdriver,', False),
        ('   audit dbusdriver,', False),
    ]

class AARegexMount(unittest.TestCase):
    '''Tests for RE_PROFILE_MOUNT'''

    def setUp(self):
        self.regex = aa.RE_PROFILE_MOUNT

    tests = [
        ('   mount,', (None, None, 'mount,', 'mount', None, None)),
        ('   audit mount,', ('audit', None, 'mount,', 'mount', None, None)),
        ('   umount,', (None, None, 'umount,', 'umount', None, None)),
        ('   audit umount,', ('audit', None, 'umount,', 'umount', None, None)),
        ('   unmount,', (None, None, 'unmount,', 'unmount', None, None)),
        ('   audit unmount,', ('audit', None, 'unmount,', 'unmount', None, None)),
        ('   remount,', (None, None, 'remount,', 'remount', None, None)),
        ('   deny remount,', (None, 'deny', 'remount,', 'remount', None, None)),

        ('   mount, # comment', (None, None, 'mount,', 'mount', None, '# comment')),

        ('   mountain,', False),
        ('   audit mountain,', False),
    ]



class AARegexSignal(unittest.TestCase):
    '''Tests for RE_PROFILE_SIGNAL'''

    def setUp(self):
        self.regex = aa.RE_PROFILE_SIGNAL

    tests = [
        ('   signal,', (None, None, 'signal,', None)),
        ('   audit signal,', ('audit', None, 'signal,', None)),
        ('   signal receive,', (None, None, 'signal receive,', None)),
        ('   signal (send, receive),',
         (None, None, 'signal (send, receive),', None)),
        ('   audit signal (receive),',
         ('audit', None, 'signal (receive),', None)),
        ('   signal (send, receive) set=(usr1 usr2),',
         (None, None, 'signal (send, receive) set=(usr1 usr2),', None)),
        ('   signal send set=(hup, quit) peer=/usr/sbin/daemon,',
         (None, None,
          'signal send set=(hup, quit) peer=/usr/sbin/daemon,', None)),

        ('   signalling,', False),
        ('   audit signalling,', False),
        ('   signalling receive,', False),
    ]


class AARegexPtrace(unittest.TestCase):
    '''Tests for RE_PROFILE_PTRACE'''

    def setUp(self):
        self.regex = aa.RE_PROFILE_PTRACE

    tests = [
        ('   ptrace,', (None, None, 'ptrace,', None)),
        ('   audit ptrace,', ('audit', None, 'ptrace,', None)),
        ('   ptrace trace,', (None, None, 'ptrace trace,', None)),
        ('   ptrace (tracedby, readby),',
         (None, None, 'ptrace (tracedby, readby),', None)),
        ('   audit ptrace (read),', ('audit', None, 'ptrace (read),', None)),
        ('   ptrace trace peer=/usr/sbin/daemon,',
         (None, None, 'ptrace trace peer=/usr/sbin/daemon,', None)),

        ('   ptraceback,', False),
        ('   audit ptraceback,', False),
        ('   ptraceback trace,', False),
    ]


class AARegexPivotRoot(unittest.TestCase):
    '''Tests for RE_PROFILE_PIVOT_ROOT'''

    def setUp(self):
        self.regex = aa.RE_PROFILE_PIVOT_ROOT

    tests = [
        ('   pivot_root,', (None, None, 'pivot_root,', None)),
        ('   audit pivot_root,', ('audit', None, 'pivot_root,', None)),
        ('   pivot_root oldroot=/new/old,',
         (None, None, 'pivot_root oldroot=/new/old,', None)),
        ('   pivot_root oldroot=/new/old /new,',
         (None, None, 'pivot_root oldroot=/new/old /new,', None)),
        ('   pivot_root oldroot=/new/old /new -> child,',
         (None, None, 'pivot_root oldroot=/new/old /new -> child,', None)),
        ('   audit pivot_root oldroot=/new/old /new -> child,',
         ('audit', None, 'pivot_root oldroot=/new/old /new -> child,', None)),

        ('pivot_root', False),  # comma missing

        ('pivot_rootbeer,', False),
        ('pivot_rootbeer    ,  ', False),
        ('pivot_rootbeer, # comment', False),
        ('pivot_rootbeer /new,  ', False),
        ('pivot_rootbeer /new, # comment', False),
    ]

class AARegexUnix(unittest.TestCase):
    '''Tests for RE_PROFILE_UNIX'''

    def setUp(self):
        self.regex = aa.RE_PROFILE_UNIX

    tests = [
        ('   unix,', (None, None, 'unix,', None)),
        ('   audit unix,', ('audit', None, 'unix,', None)),
        ('   unix accept,', (None, None, 'unix accept,', None)),
        ('   allow unix connect,', (None, 'allow', 'unix connect,', None)),
        ('   audit allow unix bind,', ('audit', 'allow', 'unix bind,', None)),
        ('   deny unix bind,', (None, 'deny', 'unix bind,', None)),
        ('unix peer=(label=@{profile_name}),',
         (None, None, 'unix peer=(label=@{profile_name}),', None)),
        ('unix (receive) peer=(label=unconfined),',
         (None, None, 'unix (receive) peer=(label=unconfined),', None)),
        (' unix (getattr, shutdown) peer=(addr=none),',
         (None, None, 'unix (getattr, shutdown) peer=(addr=none),', None)),
        ('unix (connect, receive, send) type=stream peer=(label=unconfined,addr="@/tmp/dbus-*"),',
         (None, None, 'unix (connect, receive, send) type=stream peer=(label=unconfined,addr="@/tmp/dbus-*"),', None)),
        ('unixlike', False),
        ('deny unixlike,', False),
    ]

if __name__ == '__main__':
    verbosity = 2

    setup_has_comma_testcases()
    setup_split_comment_testcases()

    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AARegexHasComma))
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AARegexSplitComment))

    for tests in (AARegexCapability, AARegexPath, AARegexBareFile,
                  AARegexDbus, AARegexMount, AARegexUnix,
                  AARegexSignal, AARegexPtrace, AARegexPivotRoot):
        setup_regex_tests(tests)
        test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(tests))

    result = unittest.TextTestRunner(verbosity=verbosity).run(test_suite)
    if not result.wasSuccessful():
        exit(1)
