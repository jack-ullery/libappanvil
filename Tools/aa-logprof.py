#!/usr/bin/python
import sys

sys.path.append('../')
import apparmor.aa
import os
import argparse

if sys.version_info < (3,0):
    os.environ['AAPATH'] = '/bin/:/sbin/:/usr/bin/:/usr/sbin'
else:
    os.environb.putenv('AAPATH', '/bin/:/sbin/:/usr/bin/:/usr/sbin')



logmark = ''

apparmor.aa.loadincludes()

apparmor.aa.do_logprof_pass(logmark)


