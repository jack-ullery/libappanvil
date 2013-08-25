#!/usr/bin/python

import argparse

from apparmor.tools import *

parser = argparse.ArgumentParser(description='Switch the given program to complain mode')
parser.add_argument('-d', type=str, help='path to profiles')
parser.add_argument('-r', '--remove', action='store_true', help='remove complain mode')
parser.add_argument('program', type=str, nargs='+', help='name of program')
args = parser.parse_args()

complain = aa_tools('complain', args)

complain.check_profile_dir()

complain.act()
