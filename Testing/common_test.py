import unittest
import re
import sys

sys.path.append('../')
import apparmor.common

class Test(unittest.TestCase):


    def test_RegexParser(self):
        regex_1 = '/foo/**/bar/'
        parsed_regex_1 = apparmor.common.convert_regexp(regex_1)
        compiled_regex_1 = re.compile(parsed_regex_1)
        #print(parsed_regex_1)
        self.assertEqual(bool(compiled_regex_1.search('/foo/user/tools/bar/')), True, 'Incorrectly Parsed regex')
        self.assertEqual(bool(compiled_regex_1.search('/foo/apparmor/bar/')), True, 'Incorrectly Parsed regex')
        
        self.assertEqual(bool(compiled_regex_1.search('/foo/apparmor/bar')), False, 'Incorrectly Parsed regex')
        
        regex_2 = '/foo/*/bar/'
        parsed_regex_2 = apparmor.common.convert_regexp(regex_2)
        compiled_regex_2 = re.compile(parsed_regex_2)
        #print(parsed_regex_2)
        self.assertEqual(bool(compiled_regex_2.search('/foo/apparmor/bar/')), True, 'Incorrectly Parsed regex')

        self.assertEqual(bool(compiled_regex_2.search('/foo/apparmor/tools/bar/')), False, 'Incorrectly Parsed regex')
        self.assertEqual(bool(compiled_regex_2.search('/foo/apparmor/bar')), False, 'Incorrectly Parsed regex')
        
        regex_3 = '/foo/{foo,bar,user,other}/bar/'
        parsed_regex_3 = apparmor.common.convert_regexp(regex_3)
        compiled_regex_3 = re.compile(parsed_regex_3)
        #print(parsed_regex_3)
        self.assertEqual(bool(compiled_regex_3.search('/foo/user/bar/')), True, 'Incorrectly Parsed regex')
        self.assertEqual(bool(compiled_regex_3.search('/foo/bar/bar/')), True, 'Incorrectly Parsed regex')
        
        self.assertEqual(bool(compiled_regex_3.search('/foo/wrong/bar/')), False, 'Incorrectly Parsed regex')
        
        regex_4 = '/foo/user/ba?/'
        parsed_regex_4 = apparmor.common.convert_regexp(regex_4)
        compiled_regex_4 = re.compile(parsed_regex_4)
        #print(parsed_regex_4)
        
        self.assertEqual(bool(compiled_regex_4.search('/foo/user/bar/')), True, 'Incorrectly Parsed regex')
        
        self.assertEqual(bool(compiled_regex_4.search('/foo/user/bar/apparmor/')), False, 'Incorrectly Parsed regex')
        self.assertEqual(bool(compiled_regex_4.search('/foo/user/ba/')), False, 'Incorrectly Parsed regex')
        
        regex_5 = '/foo/user/bar/**'
        parsed_regex_5 = apparmor.common.convert_regexp(regex_5)
        compiled_regex_5 = re.compile(parsed_regex_5)
        #print(parsed_regex_5)
        
        self.assertEqual(bool(compiled_regex_5.search('/foo/user/bar/apparmor')), True, 'Incorrectly Parsed regex')
        self.assertEqual(bool(compiled_regex_5.search('/foo/user/bar/apparmor/tools')), True, 'Incorrectly Parsed regex')
        
        self.assertEqual(bool(compiled_regex_5.search('/foo/user/bar/')), False, 'Incorrectly Parsed regex')
        
        regex_6 = '/foo/user/bar/*'
        parsed_regex_6 = apparmor.common.convert_regexp(regex_6)
        compiled_regex_6 = re.compile(parsed_regex_6)
        #print(parsed_regex_6)
        
        self.assertEqual(bool(compiled_regex_6.search('/foo/user/bar/apparmor')), True, 'Incorrectly Parsed regex')
        
        self.assertEqual(bool(compiled_regex_6.search('/foo/user/bar/apparmor/tools')), False, 'Incorrectly Parsed regex')
        self.assertEqual(bool(compiled_regex_6.search('/foo/user/bar/')), False, 'Incorrectly Parsed regex')
        
            
    def test_readkey(self):
        print("Please press the Y button on the keyboard.")
        self.assertEqual(apparmor.common.readkey().lower(), 'y', 'Error reading key from shell!')
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.test_RegexParser']
    unittest.main()