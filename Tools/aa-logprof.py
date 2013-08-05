#!/usr/bin/python
import sys

sys.path.append('../')
import apparmor.aa
import os
import argparse

os.environb.putenv('PATH', '/bin/:/sbin/:/usr/bin/:/usr/sbin')

apparmor.aa.loadincludes()


