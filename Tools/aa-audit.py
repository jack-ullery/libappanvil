#!/usr/bin/python

import argparse

from apparmor.tools import *

parser = argparse.ArgumentParser(description='Switch the given programs to audit mode')
parser.add_argument('-d', type=str, help='path to profiles')
parser.add_argument('-r', '--remove', action='store_true', help='remove audit mode')
parser.add_argument('program', type=str, nargs='+', help='name of program')
args = parser.parse_args()

audit = aa_tools('audit', args)

audit.check_profile_dir()

audit.act()
