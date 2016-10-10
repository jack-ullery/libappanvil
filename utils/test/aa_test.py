# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
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

import apparmor.aamode

class Test(unittest.TestCase):

    def setUp(self):
        self.MODE_TEST = {'x': apparmor.aamode.AA_MAY_EXEC,
                 'w': apparmor.aamode.AA_MAY_WRITE,
                 'r': apparmor.aamode.AA_MAY_READ,
                 'a': apparmor.aamode.AA_MAY_APPEND,
                 'l': apparmor.aamode.AA_MAY_LINK,
                 'k': apparmor.aamode.AA_MAY_LOCK,
                 'm': apparmor.aamode.AA_EXEC_MMAP,
                 'i': apparmor.aamode.AA_EXEC_INHERIT,
                 'u': apparmor.aamode.AA_EXEC_UNCONFINED | apparmor.aamode.AA_EXEC_UNSAFE,
                  'U': apparmor.aamode.AA_EXEC_UNCONFINED,
                  'p': apparmor.aamode.AA_EXEC_PROFILE | apparmor.aamode.AA_EXEC_UNSAFE,
                  'P': apparmor.aamode.AA_EXEC_PROFILE,
                  'c': apparmor.aamode.AA_EXEC_CHILD | apparmor.aamode.AA_EXEC_UNSAFE,
                  'C': apparmor.aamode.AA_EXEC_CHILD,
                  }

    def test_string_to_modes(self):

        for string in self.MODE_TEST.keys():
            mode = self.MODE_TEST[string] | apparmor.aamode.AA_OTHER(self.MODE_TEST[string])
            #print("mode: %s string: %s str_to_mode(string): %s" % (mode, string,  apparmor.aamode.str_to_mode(string)))
            self.assertEqual(mode, apparmor.aamode.str_to_mode(string), 'mode is %s and string is %s'%(mode, string))


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main(verbosity=2)
