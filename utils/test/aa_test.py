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

import apparmor.aa
import apparmor.logparser

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

    def test_loadinclude(self):
        apparmor.aa.loadincludes()

    def test_path_globs(self):
        globs = {
                 '/foo/': '/*/',
                 '/foo': '/*',
                 '/b*': '/*',
                 '/*b': '/*',
                 '/*': '/*',
                 '/*/': '/*/',
                 '/*.foo/': '/*/',
                 '/**.foo/': '/**/',
                 '/foo/*/': '/**/',
                 '/usr/foo/*': '/usr/**',
                 '/usr/foo/**': '/usr/**',
                 '/usr/foo/bar**': '/usr/foo/**',
                 '/usr/foo/**bar': '/usr/foo/**',
                 '/usr/bin/foo**bar': '/usr/bin/**',
                 '/usr/foo/**/bar': '/usr/foo/**/*',
                 '/usr/foo/**/*': '/usr/foo/**',
                 '/usr/foo/*/bar': '/usr/foo/*/*',
                 '/usr/bin/foo*bar': '/usr/bin/*',
                 '/usr/bin/*foo*': '/usr/bin/*',
                 '/usr/foo/*/*': '/usr/foo/**',
                 '/usr/foo/*/**': '/usr/foo/**',
                 '/**': '/**',
                 '/**/': '/**/'
                 }
        for path in globs.keys():
            self.assertEqual(apparmor.aa.glob_path(path), globs[path], 'Unexpected glob generated for path: %s'%path)

    def test_path_withext_globs(self):
        globs = {
                 '/foo/bar': '/foo/bar',
                 '/foo/**/bar': '/foo/**/bar',
                 '/foo.bar': '/*.bar',
                 '/*.foo': '/*.foo' ,
                 '/usr/*.bar': '/**.bar',
                 '/usr/**.bar': '/**.bar',
                 '/usr/foo**.bar': '/usr/**.bar',
                 '/usr/foo*.bar': '/usr/*.bar',
                 '/usr/fo*oo.bar': '/usr/*.bar',
                 '/usr/*foo*.bar': '/usr/*.bar',
                 '/usr/**foo.bar': '/usr/**.bar',
                 '/usr/*foo.bar': '/usr/*.bar',
                 '/usr/foo.b*': '/usr/*.b*'
                 }
        for path in globs.keys():
            self.assertEqual(apparmor.aa.glob_path_withext(path), globs[path], 'Unexpected glob generated for path: %s'%path)

    def test_parse_event(self):
        parser = apparmor.logparser.ReadLog('', '', '', '', '')
        event = 'type=AVC msg=audit(1345027352.096:499): apparmor="ALLOWED" operation="rename_dest" parent=6974 profile="/usr/sbin/httpd2-prefork//vhost_foo" name=2F686F6D652F7777772F666F6F2E6261722E696E2F68747470646F63732F61707061726D6F722F696D616765732F746573742F696D61676520312E6A7067 pid=20143 comm="httpd2-prefork" requested_mask="wc" denied_mask="wc" fsuid=30 ouid=30'
        parsed_event = parser.parse_event(event)
        self.assertEqual(parsed_event['name'], '/home/www/foo.bar.in/httpdocs/apparmor/images/test/image 1.jpg', 'Incorrectly parsed/decoded name')
        self.assertEqual(parsed_event['profile'], '/usr/sbin/httpd2-prefork//vhost_foo', 'Incorrectly parsed/decode profile name')
        self.assertEqual(parsed_event['aamode'], 'PERMITTING')
        self.assertEqual(parsed_event['request_mask'], set(['w', 'a', '::w', '::a']))
        #print(parsed_event)

        #event = 'type=AVC msg=audit(1322614912.304:857): apparmor="ALLOWED" operation="getattr" parent=16001 profile=74657374207370616365 name=74657374207370616365 pid=17011 comm="bash" requested_mask="r" denied_mask="r" fsuid=0 ouid=0'
        #parsed_event = apparmor.aa.parse_event(event)
        #print(parsed_event)

        event = 'type=AVC msg=audit(1322614918.292:4376): apparmor="ALLOWED" operation="file_perm" parent=16001 profile=666F6F20626172 name="/home/foo/.bash_history" pid=17011 comm="bash" requested_mask="rw" denied_mask="rw" fsuid=0 ouid=1000'
        parsed_event = parser.parse_event(event)
        self.assertEqual(parsed_event['name'], '/home/foo/.bash_history', 'Incorrectly parsed/decoded name')
        self.assertEqual(parsed_event['profile'], 'foo bar', 'Incorrectly parsed/decode profile name')
        self.assertEqual(parsed_event['aamode'], 'PERMITTING')
        self.assertEqual(parsed_event['request_mask'], set(['r', 'w', 'a','::r' , '::w', '::a']))
        #print(parsed_event)


    def test_modes_to_string(self):

        for string in self.MODE_TEST.keys():
            mode = self.MODE_TEST[string]
            self.assertEqual(apparmor.aamode.mode_to_str(mode), string, 'mode is %s and string is %s'%(mode, string))

    def test_string_to_modes(self):

        for string in self.MODE_TEST.keys():
            mode = self.MODE_TEST[string] | apparmor.aamode.AA_OTHER(self.MODE_TEST[string])
            #print("mode: %s string: %s str_to_mode(string): %s" % (mode, string,  apparmor.aamode.str_to_mode(string)))
            self.assertEqual(mode, apparmor.aamode.str_to_mode(string), 'mode is %s and string is %s'%(mode, string))


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main(verbosity=2)
