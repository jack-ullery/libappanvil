#! /usr/bin/env python
# ------------------------------------------------------------------
#
#    Copyright (C) 2014 Canonical Ltd.
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import apparmor.aa as aa
import unittest

class AAParseDBUSTest(unittest.TestCase):

    def test_parse_plain_dbus_rule(self):
        dstring = 'dbus,'
        dbus = aa.parse_dbus_rule(dstring)
        self.assertEqual(dstring, dbus.serialize(),
                'dbus object returned "%s", expected "%s"' % (dbus.serialize(), dstring))

    def test_parse_dbus_simple_send_rule(self):
        dstring = 'dbus send,'
        dbus = aa.parse_dbus_rule(dstring)
        self.assertEqual(dstring, dbus.serialize(),
                'dbus object returned "%s", expected "%s"' % (dbus.serialize(), dstring))

if __name__ == '__main__':
    unittest.main(verbosity=2)
