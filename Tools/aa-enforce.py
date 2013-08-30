#!/usr/bin/python

import argparse

import apparmor.tools

parser = argparse.ArgumentParser(description='Switch the given program to enforce mode')
parser.add_argument('-d', type=str, help='path to profiles')
parser.add_argument('-r', '--remove', action='store_true', help='switch to complain mode')
parser.add_argument('program', type=str, nargs='+', help='name of program')
args = parser.parse_args()
# Flipping the remove flag since complain = !enforce
args.remove = not args.remove

enforce = apparmor.tools.aa_tools('complain', args)

enforce.act()
