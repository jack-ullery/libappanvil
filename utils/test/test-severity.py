#!/usr/bin/env python
# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#    Copyright (C) 2014 Canonical, Ltd.
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
import tempfile
import unittest

import apparmor.severity as severity
from apparmor.common import AppArmorException
from common_test import write_file

class SeverityBaseTest(unittest.TestCase):

    def setUp(self):
        self.sev_db = severity.Severity('severity.db')

    def tearDown(self):
        pass

    def _simple_severity_test(self, path, expected_rank):
        rank = self.sev_db.rank(path)
        self.assertEqual(rank, expected_rank,
                         'expected rank %d, got %d' % (expected_rank, rank))

    def _simple_severity_w_perm(self, path, perm, expected_rank):
        rank = self.sev_db.rank(path, perm)
        self.assertEqual(rank, expected_rank,
                         'expected rank %d, got %d' % (expected_rank, rank))

class SeverityTest(SeverityBaseTest):
    def test_perm_x(self):
        self._simple_severity_w_perm('/usr/bin/whatis', 'x', 5)

    def test_perm_etc_x(self):
        self._simple_severity_w_perm('/etc', 'x', 10)

    def test_perm_dev_x(self):
        self._simple_severity_w_perm('/dev/doublehit', 'x', 0)

    def test_perm_dev_rx(self):
        self._simple_severity_w_perm('/dev/doublehit', 'rx', 4)

    def test_perm_dev_rwx(self):
        self._simple_severity_w_perm('/dev/doublehit', 'rwx', 8)

    def test_perm_tty_rwx(self):
        self._simple_severity_w_perm('/dev/tty10', 'rwx', 9)

    def test_perm_glob_1(self):
        self._simple_severity_w_perm('/var/adm/foo/**', 'rx', 3)

    def test_cap_kill(self):
        self._simple_severity_test('CAP_KILL', 8)

    def test_cap_setpcap(self):
        self._simple_severity_test('CAP_SETPCAP', 9)

    def test_cap_setpcap_lowercase(self):
        self._simple_severity_test('CAP_setpcap', 9)

    def test_cap_unknown_1(self):
        self._simple_severity_test('CAP_UNKNOWN', 10)

    def test_cap_unknown_2(self):
        self._simple_severity_test('CAP_K*', 10)

    def test_perm_apparmor_glob(self):
        self._simple_severity_w_perm('/etc/apparmor/**', 'r' , 6)

    def test_perm_etc_glob(self):
        self._simple_severity_w_perm('/etc/**', 'r' , 10)

    def test_perm_filename_w_at_r(self):
        self._simple_severity_w_perm('/usr/foo@bar', 'r' , 10)  ## filename containing @

    def test_perm_filename_w_at_rw(self):
        self._simple_severity_w_perm('/home/foo@bar', 'rw', 6)  ## filename containing @

    def test_invalid_rank(self):
        with self.assertRaises(AppArmorException):
            self._simple_severity_w_perm('unexpected_unput', 'rw', 6)

class SeverityVarsTest(SeverityBaseTest):

    VARIABLE_DEFINITIONS = '''
@{HOME}=@{HOMEDIRS}/*/ /root/
@{HOMEDIRS}=/home/
# add another path to @{HOMEDIRS}
@{HOMEDIRS}+=/storage/
@{multiarch}=*-linux-gnu*
@{TFTP_DIR}=/var/tftp /srv/tftpboot
@{PROC}=/proc/
@{pid}={[1-9],[1-9][0-9],[1-9][0-9][0-9],[1-9][0-9][0-9][0-9],[1-9][0-9][0-9][0-9][0-9],[1-9][0-9][0-9][0-9][0-9][0-9]}
@{tid}=@{pid}
@{pids}=@{pid}
'''

    def setUp(self):
        super(SeverityVarsTest, self).setUp()
        self.tmpdir = tempfile.mkdtemp(prefix='aa-severity-')

    def _init_tunables(self, content=''):
        if not content:
            content = self.VARIABLE_DEFINITIONS

        self.rules_file = write_file(self.tmpdir, 'tunables', content)

        self.sev_db.load_variables(self.rules_file)

    def tearDown(self):
        self.sev_db.unload_variables()
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

        super(SeverityVarsTest, self).tearDown()

    def test_proc_var(self):
        self._init_tunables()
        self._simple_severity_w_perm('@{PROC}/sys/vm/overcommit_memory', 'r', 6)

    def test_home_var(self):
        self._init_tunables()
        self._simple_severity_w_perm('@{HOME}/sys/@{PROC}/overcommit_memory', 'r', 10)

    def test_multiarch_var(self):
        self._init_tunables()
        self._simple_severity_w_perm('/overco@{multiarch}mmit_memory', 'r', 10)

    def test_proc_tftp_vars(self):
        self._init_tunables()
        self._simple_severity_w_perm('@{PROC}/sys/@{TFTP_DIR}/overcommit_memory', 'r', 6)

    def test_include(self):
        self._init_tunables('#include <file/not/found>')  # including non-existing files doesn't raise an exception

        self.assertTrue(True)  # this test only makes sure that loading the tunables file works

    def test_invalid_variable_add(self):
        with self.assertRaises(AppArmorException):
            self._init_tunables('@{invalid} += /home/')

    def test_invalid_variable_double_definition(self):
        invalid_add = '@{foo} = /home/\n@{foo} = /root/'
        with self.assertRaises(AppArmorException):
            self._init_tunables('@{foo} = /home/\n@{foo} = /root/')

class SeverityDBTest(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='aa-severity-db-')

    def tearDown(self):
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def _test_db(self, contents):
        self.db_file = write_file(self.tmpdir, 'severity.db', contents)
        self.sev_db = severity.Severity(self.db_file)
        return self.sev_db

    def test_simple_db(self):
        self._test_db('''
    CAP_LEASE 8
    /etc/passwd*    4 8 0
''')

    def test_cap_val_max_range(self):
        self._test_db("CAP_LEASE 10\n")

    def test_cap_val_min_range(self):
        self._test_db("CAP_LEASE 0\n")

    def test_cap_val_out_of_range_1(self):
        with self.assertRaises(AppArmorException):
            self._test_db("CAP_LEASE 18\n")

    def test_cap_val_out_of_range_2(self):
        with self.assertRaises(AppArmorException):
            self._test_db("CAP_LEASE -1\n")

    def test_path_insufficient_vals(self):
        with self.assertRaises(AppArmorException):
            self._test_db("/etc/passwd* 0 4\n")

    def test_path_too_many_vals(self):
        with self.assertRaises(AppArmorException):
            self._test_db("/etc/passwd* 0 4 5 6\n")

    def test_path_outside_range_1(self):
        with self.assertRaises(AppArmorException):
            self._test_db("/etc/passwd* -2 4 6\n")

    def test_path_outside_range_2(self):
        with self.assertRaises(AppArmorException):
            self._test_db("/etc/passwd* 12 4 6\n")

    def test_path_outside_range_3(self):
        with self.assertRaises(AppArmorException):
            self._test_db("/etc/passwd* 2 -4 6\n")

    def test_path_outside_range_4(self):
        with self.assertRaises(AppArmorException):
            self._test_db("/etc/passwd 2 14 6\n")

    def test_path_outside_range_5(self):
        with self.assertRaises(AppArmorException):
            self._test_db("/etc/passwd 2 4 -12\n")

    def test_path_outside_range_6(self):
        with self.assertRaises(AppArmorException):
            self._test_db("/etc/passwd 2 4 4294967297\n")

    def test_garbage_line(self):
        with self.assertRaises(AppArmorException):
            self._test_db("garbage line\n")

    def test_invalid_db(self):
        self.assertRaises(AppArmorException, severity.Severity, 'severity_broken.db')

    def test_nonexistent_db(self):
        self.assertRaises(IOError, severity.Severity, 'severity.db.does.not.exist')

    def test_no_arg_to_severity(self):
        with self.assertRaises(AppArmorException):
            severity.Severity()

if __name__ == "__main__":
    unittest.main(verbosity=2)
