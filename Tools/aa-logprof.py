#!/usr/bin/python
import sys

sys.path.append('../')
import apparmor.aa
import os
import argparse

logmark = ''

apparmor.aa.loadincludes()

apparmor.aa.do_logprof_pass(logmark)


