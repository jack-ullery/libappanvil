'''
Created on Jun 21, 2013

@author: kshitij
'''
import sys
import unittest
sys.path.append('../lib')

import severity

class Test(unittest.TestCase):


    def testName(self):
        z = severity.Severity()
        s = severity.Severity('severity.db')
        cases_file = [('/usr/bin/whatis', 'x'), ('/etc', 'x'), ('/dev/doublehit', 'x')]
        cases_cap = ['CAP_SETPCAP', 'CAP_KILL']
        for case in cases_file:
            rank = s.rank(case[0], case[1])
            self.assertIn(rank, range(0,11), "Invalid rank")
            print(rank)
        for case in cases_cap:
            rank = s.rank(case)
            self.assertIn(rank, range(0,11), "Invalid rank")
            print(rank)
        


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()