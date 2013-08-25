#!/usr/bin/python

import argparse

from apparmor.tools import *

parser = argparse.ArgumentParser(description='')
parser.add_argument('--force', type=str, help='path to profiles')
parser.add_argument('-d', type=str, help='path to profiles')
parser.add_argument('program', type=str, nargs='+', help='name of program')
args = parser.parse_args()

autodep = aa_tools('autodep', args)

autodep.check_profile_dir()

autodep.act()