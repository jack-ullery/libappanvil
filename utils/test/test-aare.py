#! /usr/bin/env python
# ------------------------------------------------------------------
#
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#    Copyright (C) 2015 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import unittest
from common_test import AATest, setup_all_loops

import re
from apparmor.common import convert_regexp

class TestConvert_regexp(AATest):
    tests = [
        ('/foo',                '^/foo$'),
        ('/{foo,bar}',          '^/(foo|bar)$'),
        # ('/\{foo,bar}',         '^/\{foo,bar}$'), # XXX gets converted to ^/\(foo|bar)$
        ('/fo[abc]',            '^/fo[abc]$'),
        ('/foo bar',            '^/foo bar$'),
        ('/x\y',                '^/x\y$'),
        ('/x\[y',               '^/x\[y$'),
        ('/x\\y',               '^/x\\y$'),
        ('/fo?',                '^/fo[^/\000]$'),
        ('/foo/*',              '^/foo/(((?<=/)[^/\000]+)|((?<!/)[^/\000]*))$'),
        ('/foo/**.bar',         '^/foo/(((?<=/)[^\000]+)|((?<!/)[^\000]*))\.bar$'),
    ]

    def _run_test(self, params, expected):
        self.assertEqual(convert_regexp(params), expected)

class TestExamplesConvert_regexp(AATest):
    tests = [
        #  aare                  path to check                         match expected?
        (['/foo/**/bar/',       '/foo/user/tools/bar/'              ], True),
        (['/foo/**/bar/',       '/foo/apparmor/bar/'                ], True),
        (['/foo/**/bar/',       '/foo/apparmor/bar'                 ], False),
        (['/foo/**/bar/',       '/a/foo/apparmor/bar/'              ], False),
        (['/foo/**/bar/',       '/foo/apparmor/bar/baz'             ], False),

        (['/foo/*/bar/',        '/foo/apparmor/bar/'                ], True),
        (['/foo/*/bar/',        '/foo/apparmor/tools/bar/'          ], False),
        (['/foo/*/bar/',        '/foo/apparmor/bar'                 ], False),

        (['/foo/user/ba?/',     '/foo/user/bar/'                    ], True),
        (['/foo/user/ba?/',     '/foo/user/bar/apparmor/'           ], False),
        (['/foo/user/ba?/',     '/foo/user/ba/'                     ], False),
        (['/foo/user/ba?/',     '/foo/user/ba//'                    ], False),

        (['/foo/user/bar/**',   '/foo/user/bar/apparmor'            ], True),
        (['/foo/user/bar/**',   '/foo/user/bar/apparmor/tools'      ], True),
        (['/foo/user/bar/**',   '/foo/user/bar/'                    ], False),

        (['/foo/user/bar/*',    '/foo/user/bar/apparmor'            ], True),
        (['/foo/user/bar/*',    '/foo/user/bar/apparmor/tools'      ], False),
        (['/foo/user/bar/*',    '/foo/user/bar/'                    ], False),
        (['/foo/user/bar/*',    '/foo/user/bar/apparmor/'           ], False),

        (['/foo/**.jpg',        '/foo/bar/baz/foobar.jpg'           ], True),
        (['/foo/**.jpg',        '/foo/bar/foobar.jpg'               ], True),
        (['/foo/**.jpg',        '/foo/bar/*.jpg'                    ], True),
        (['/foo/**.jpg',        '/foo/bar.jpg'                      ], True),
        (['/foo/**.jpg',        '/foo/**.jpg'                       ], True),
        (['/foo/**.jpg',        '/foo/*.jpg'                        ], True),
        (['/foo/**.jpg',        '/foo/barjpg'                       ], False),
        (['/foo/**.jpg',        '/foo/.*'                           ], False),
        (['/foo/**.jpg',        '/bar.jpg'                          ], False),
        (['/foo/**.jpg',        '/**.jpg'                           ], False),
        (['/foo/**.jpg',        '/*.jpg'                            ], False),
        (['/foo/**.jpg',        '/foo/*.bar'                        ], False),

        (['/foo/{**,}',         '/foo/'                             ], True),
        (['/foo/{**,}',         '/foo/bar'                          ], True),
        (['/foo/{**,}',         '/foo/bar/'                         ], True),
        (['/foo/{**,}',         '/foo/bar/baz'                      ], True),
        (['/foo/{**,}',         '/foo/bar/baz/'                     ], True),
        (['/foo/{**,}',         '/bar/'                             ], False),

        (['/foo/{,**}',         '/foo/'                             ], True),
        (['/foo/{,**}',         '/foo/bar'                          ], True),
        (['/foo/{,**}',         '/foo/bar/'                         ], True),
        (['/foo/{,**}',         '/foo/bar/baz'                      ], True),
        (['/foo/{,**}',         '/foo/bar/baz/'                     ], True),
        (['/foo/{,**}',         '/bar/'                             ], False),

        (['/foo/a[bcd]e',       '/foo/abe'                          ], True),
        (['/foo/a[bcd]e',       '/foo/abend'                        ], False),
        (['/foo/a[bcd]e',       '/foo/axe'                          ], False),

        (['/foo/a[b-d]e',       '/foo/abe'                          ], True),
        (['/foo/a[b-d]e',       '/foo/ace'                          ], True),
        (['/foo/a[b-d]e',       '/foo/abend'                        ], False),
        (['/foo/a[b-d]e',       '/foo/axe'                          ], False),

        (['/foo/a[^bcd]e',      '/foo/abe'                          ], False),
        (['/foo/a[^bcd]e',      '/foo/abend'                        ], False),
        (['/foo/a[^bcd]e',      '/foo/axe'                          ], True),

        (['/foo/{foo,bar,user,other}/bar/',                         '/foo/user/bar/'                ], True),
        (['/foo/{foo,bar,user,other}/bar/',                         '/foo/bar/bar/'                 ], True),
        (['/foo/{foo,bar,user,other}/bar/',                         '/foo/wrong/bar/'               ], False),

        (['/foo/{foo,bar,user,other}/test,ca}se/{aa,sd,nd}/bar/',   '/foo/user/test,ca}se/aa/bar/'  ], True),
        (['/foo/{foo,bar,user,other}/test,ca}se/{aa,sd,nd}/bar/',   '/foo/bar/test,ca}se/sd/bar/'   ], True),
        (['/foo/{foo,bar,user,other}/test,ca}se/{aa,sd,nd}/bar/',   '/foo/wrong/user/bar/'          ], False),
        (['/foo/{foo,bar,user,other}/test,ca}se/{aa,sd,nd}/bar/',   '/foo/user/wrong/bar/'          ], False),
        (['/foo/{foo,bar,user,other}/test,ca}se/{aa,sd,nd}/bar/',   '/foo/wrong/aa/bar/'            ], False),
    ]

    def _run_test(self, params, expected):
        regex, path = params
        parsed_regex = re.compile(convert_regexp(regex))
        self.assertEqual(bool(parsed_regex.search(path)), expected, 'Incorrectly Parsed regex: %s' %regex)


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=2)
