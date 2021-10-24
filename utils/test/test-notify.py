#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2021 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import unittest
from common_test import AATest, setup_all_loops

from apparmor.notify import get_last_login_timestamp

class TestGet_last_login_timestamp(AATest):
    tests = [
        (['wtmp-x86_64',        'root'      ], 1635070346),  # Sun Oct 24 12:12:26 CEST 2021
        (['wtmp-x86_64',        'whoever'   ], 0),
    ]

    def _run_test(self, params, expected):
        filename, user = params
        filename = 'wtmp-examples/%s' % filename
        self.assertEqual(get_last_login_timestamp(user, filename), expected)


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
