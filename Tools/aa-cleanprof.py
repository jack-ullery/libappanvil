#!/usr/bin/python

import argparse

import apparmor.tools

parser = argparse.ArgumentParser(description='Cleanup the profiles for the given programs')
parser.add_argument('-d', type=str, help='path to profiles')
parser.add_argument('program', type=str, nargs='+', help='name of program')
args = parser.parse_args()

clean = apparmor.tools.aa_tools('cleanprof', args)

clean.act()