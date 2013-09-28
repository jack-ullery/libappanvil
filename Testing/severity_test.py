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
import os
import shutil
import sys
import unittest

sys.path.append('../')

import apparmor.severity as severity
from apparmor.common import AppArmorException

class Test(unittest.TestCase):

    def setUp(self):
        #copy the local profiles to the test directory
        if os.path.exists('./profiles'):
            shutil.rmtree('./profiles')
        shutil.copytree('/etc/apparmor.d/', './profiles/', symlinks=True)

    def tearDown(self):
        #Wipe the local profiles from the test directory
        shutil.rmtree('./profiles')

    def testRank_Test(self):
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

        # Load all variables for /sbin/klogd and test them
        s.load_variables('profiles/sbin.klogd')
        self.assertEqual(s.rank('@{PROC}/sys/vm/overcommit_memory', 'r'), 6, 'Invalid Rank')
        self.assertEqual(s.rank('@{HOME}/sys/@{PROC}/overcommit_memory', 'r'), 10, 'Invalid Rank')
        self.assertEqual(s.rank('/overco@{multiarch}mmit_memory', 'r'), 10, 'Invalid Rank')

        s.unload_variables()

        s.load_variables('profiles/usr.sbin.dnsmasq')
        self.assertEqual(s.rank('@{PROC}/sys/@{TFTP_DIR}/overcommit_memory', 'r'), 6, 'Invalid Rank')
        self.assertEqual(s.rank('@{PROC}/sys/vm/overcommit_memory', 'r'), 6, 'Invalid Rank')
        self.assertEqual(s.rank('@{HOME}/sys/@{PROC}/overcommit_memory', 'r'), 10, 'Invalid Rank')
        self.assertEqual(s.rank('/overco@{multiarch}mmit_memory', 'r'), 10, 'Invalid Rank')

        #self.assertEqual(s.rank('/proc/@{PID}/maps', 'rw'), 9, 'Invalid Rank')

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



if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()