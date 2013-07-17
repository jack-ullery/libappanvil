'''
Created on Jun 21, 2013

@author: kshitij
'''
import sys
import unittest

sys.path.append('../')

import apparmor.severity as severity
from apparmor.common import AppArmorException
class Test(unittest.TestCase):

    def testInvalid(self):
        s = severity.Severity('severity.db')
        rank = s.rank('/dev/doublehit', 'i')  
        self.assertEqual(rank, 10, 'Wrong') 
        try:
            broken = severity.Severity('severity_broken.db')   
        except AppArmorException:
            pass
        rank =  s.rank('CAP_UNKOWN')
        rank =  s.rank('CAP_K*')    
        
    def testRank_Test(self):
        z = severity.Severity()
        s = severity.Severity('severity.db')
        rank = s.rank('/usr/bin/whatis', 'x')
        self.assertEqual(rank, 5, 'Wrong rank')
        rank = s.rank('/etc', 'x')
        self.assertEqual(rank, 10, 'Wrong rank')
        rank = s.rank('/dev/doublehit', 'x')
        self.assertEqual(rank, 0, 'Wrong rank')
        rank = s.rank('/dev/doublehit', 'rx')
        self.assertEqual(rank, 4, 'Wrong rank')
        rank = s.rank('/dev/doublehit', 'rwx')
        self.assertEqual(rank, 8, 'Wrong rank')
        rank = s.rank('/dev/tty10', 'rwx')
        self.assertEqual(rank, 9, 'Wrong rank')
        rank = s.rank('/var/adm/foo/**', 'rx')
        self.assertEqual(rank, 3, 'Wrong rank')
        rank = s.rank('CAP_KILL')
        self.assertEqual(rank, 8, 'Wrong rank')
        rank = s.rank('CAP_SETPCAP')
        self.assertEqual(rank, 9, 'Wrong rank')
        self.assertEqual(s.rank('/etc/apparmor/**', 'r') , 6,  'Invalid Rank')
        self.assertEqual(s.rank('/etc/**', 'r') , 10,  'Invalid Rank')
        self.assertEqual(s.rank('@{PROC}/sys/vm/overcommit_memory', 'r'), 6, 'Invalid Rank')
        self.assertEqual(s.rank('@{HOME}/sys/@{PROC}/overcommit_memory', 'r'), 10, 'Invalid Rank')
        self.assertEqual(s.rank('@{PROC}/sys/@{TFTP_DIR}/overcommit_memory', 'r'), 6, 'Invalid Rank')
        self.assertEqual(s.rank('/overco@{multiarch}mmit_memory', 'r'), 10, 'Invalid Rank')
        
        #self.assertEqual(s.rank('/proc/@{PID}/maps', 'rw'), 9, 'Invalid Rank')
        

        
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()