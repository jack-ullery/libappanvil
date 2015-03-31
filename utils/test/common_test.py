# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#    Copyright (C) 2015 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
# ----------------------------------------------------------------------
import unittest
import inspect
import os
import re
import sys

import apparmor.common
import apparmor.config

class Test(unittest.TestCase):


    def test_RegexParser(self):
        tests = apparmor.config.Config('ini')
        tests.CONF_DIR = '.'
        regex_tests = tests.read_config('regex_tests.ini')
        for regex in regex_tests.sections():
            parsed_regex = re.compile(apparmor.common.convert_regexp(regex))
            for regex_testcase in regex_tests.options(regex):
                self.assertEqual(bool(parsed_regex.search(regex_testcase)), eval(regex_tests[regex][regex_testcase]), 'Incorrectly Parsed regex: %s' %regex)

    #def test_readkey(self):
    #    print("Please press the Y button on the keyboard.")
    #    self.assertEqual(apparmor.common.readkey().lower(), 'y', 'Error reading key from shell!')


class AATest(unittest.TestCase):
    tests = []

class AAParseTest(unittest.TestCase):
    parse_function = None

    def _test_parse_rule(self, rule):
        self.assertIsNot(self.parse_function, 'Test class did not set a parse_function')
        parsed = self.parse_function(rule)
        self.assertEqual(rule, parsed.serialize(),
            'parse object %s returned "%s", expected "%s"' \
            %(self.parse_function.__doc__, parsed.serialize(), rule))


def setup_all_tests():
    '''call setup_tests_loop() for each class in module_name'''
    for name, obj in inspect.getmembers(sys.modules['__main__']):
        if inspect.isclass(obj):
            if issubclass(obj, unittest.TestCase):
                setup_tests_loop(obj)

def setup_tests_loop(test_class):
    '''Create tests in test_class using test_class.tests and self._run_test()

    test_class.tests should be tuples of (test_data, expected_results)
    test_data and expected_results can be of any type as long as test_class._run_test()
    know how to handle them.

    A typical definition for _run_test() is:
        def test_class._run_test(self, test_data, expected)
        '''

    for (i, (test_data, expected)) in enumerate(test_class.tests):
        def stub_test(self, test_data=test_data, expected=expected):
            self._run_test(test_data, expected)

        stub_test.__doc__ = "test '%s'" % (test_data)
        setattr(test_class, 'test_%d' % (i), stub_test)


def setup_regex_tests(test_class):
    '''Create tests in test_class using test_class.tests and AAParseTest._test_parse_rule()

    test_class.tests should be tuples of (line, description)
    '''
    for (i, (line, desc)) in enumerate(test_class.tests):
        def stub_test(self, line=line):
            self._test_parse_rule(line)

        stub_test.__doc__ = "test '%s': %s" % (line, desc)
        setattr(test_class, 'test_%d' % (i), stub_test)

def write_file(directory, file, contents):
    '''construct path, write contents to it, and return the constructed path'''
    path = os.path.join(directory, file)
    with open(path, 'w+') as f:
        f.write(contents)
    return path

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.test_RegexParser']
    unittest.main()
