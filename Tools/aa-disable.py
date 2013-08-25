#!/usr/bin/python

import argparse

from apparmor.tools import *
import apparmor.aa as apparmor

parser = argparse.ArgumentParser(description='Disable the profile for the given programs')
parser.add_argument('-d', type=str, help='path to profiles')
parser.add_argument('-r', '--revert', action='store_true', help='enable the profile for the given programs')
parser.add_argument('program', type=str, nargs='+', help='name of program')
args = parser.parse_args()

disable = aa_tools('disable', args)

disable.check_profile_dir()
disable.check_disable_dir()

disable.act()

