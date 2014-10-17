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
import unittest

import apparmor.severity as severity
from apparmor.common import AppArmorException

class Test(unittest.TestCase):

    def setUp(self):
        #copy the local profiles to the test directory
        if os.path.exists('./profiles'):
            shutil.rmtree('./profiles')
        shutil.copytree('../../profiles/apparmor.d/', './profiles/', symlinks=True)

    def tearDown(self):
        #Wipe the local profiles from the test directory
        shutil.rmtree('./profiles')

    def testRank_Test(self):
        sev_db = severity.Severity('severity.db')
        rank = sev_db.rank('/usr/bin/whatis', 'x')
        self.assertEqual(rank, 5, 'Wrong rank')
        rank = sev_db.rank('/etc', 'x')
        self.assertEqual(rank, 10, 'Wrong rank')
        rank = sev_db.rank('/dev/doublehit', 'x')
        self.assertEqual(rank, 0, 'Wrong rank')
        rank = sev_db.rank('/dev/doublehit', 'rx')
        self.assertEqual(rank, 4, 'Wrong rank')
        rank = sev_db.rank('/dev/doublehit', 'rwx')
        self.assertEqual(rank, 8, 'Wrong rank')
        rank = sev_db.rank('/dev/tty10', 'rwx')
        self.assertEqual(rank, 9, 'Wrong rank')
        rank = sev_db.rank('/var/adm/foo/**', 'rx')
        self.assertEqual(rank, 3, 'Wrong rank')
        rank = sev_db.rank('CAP_KILL')
        self.assertEqual(rank, 8, 'Wrong rank')
        rank = sev_db.rank('CAP_SETPCAP')
        self.assertEqual(rank, 9, 'Wrong rank')
        self.assertEqual(sev_db.rank('/etc/apparmor/**', 'r') , 6,  'Invalid Rank')
        self.assertEqual(sev_db.rank('/etc/**', 'r') , 10,  'Invalid Rank')
        self.assertEqual(sev_db.rank('/usr/foo@bar', 'r') , 10,  'Invalid Rank')  ## filename containing @
        self.assertEqual(sev_db.rank('/home/foo@bar', 'rw') , 6,  'Invalid Rank')  ## filename containing @

        # Load all variables for /sbin/klogd and test them
        sev_db.load_variables('profiles/sbin.klogd')
        self.assertEqual(sev_db.rank('@{PROC}/sys/vm/overcommit_memory', 'r'), 6, 'Invalid Rank')
        self.assertEqual(sev_db.rank('@{HOME}/sys/@{PROC}/overcommit_memory', 'r'), 10, 'Invalid Rank')
        self.assertEqual(sev_db.rank('/overco@{multiarch}mmit_memory', 'r'), 10, 'Invalid Rank')

        sev_db.unload_variables()

        sev_db.load_variables('profiles/usr.sbin.dnsmasq')
        self.assertEqual(sev_db.rank('@{PROC}/sys/@{TFTP_DIR}/overcommit_memory', 'r'), 6, 'Invalid Rank')
        self.assertEqual(sev_db.rank('@{PROC}/sys/vm/overcommit_memory', 'r'), 6, 'Invalid Rank')
        self.assertEqual(sev_db.rank('@{HOME}/sys/@{PROC}/overcommit_memory', 'r'), 10, 'Invalid Rank')
        self.assertEqual(sev_db.rank('/overco@{multiarch}mmit_memory', 'r'), 10, 'Invalid Rank')

        #self.assertEqual(sev_db.rank('/proc/@{PID}/maps', 'rw'), 9, 'Invalid Rank')

    def testInvalid(self):
        sev_db = severity.Severity('severity.db')
        rank = sev_db.rank('/dev/doublehit', 'i')
        self.assertEqual(rank, 10, 'Wrong')
        try:
            severity.Severity('severity_broken.db')
        except AppArmorException:
            pass
        rank =  sev_db.rank('CAP_UNKOWN')
        rank =  sev_db.rank('CAP_K*')



if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
