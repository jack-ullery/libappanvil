import unittest
import re
import sys

sys.path.append('../')
import apparmor.common
import apparmor.config

class Test(unittest.TestCase):


    def test_RegexParser(self):
        tests=apparmor.config.Config('ini')
        tests.CONF_DIR = '.'
        regex_tests = tests.read_config('regex_tests.ini')
        for regex in regex_tests.sections():
            parsed_regex = re.compile(apparmor.common.convert_regexp(regex))
            for regex_testcase in regex_tests.options(regex):
                self.assertEqual(bool(parsed_regex.search(regex_testcase)), eval(regex_tests[regex][regex_testcase]), 'Incorrectly Parsed regex')
           
    #def test_readkey(self):
    #    print("Please press the Y button on the keyboard.")
    #    self.assertEqual(apparmor.common.readkey().lower(), 'y', 'Error reading key from shell!')
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.test_RegexParser']
    unittest.main()