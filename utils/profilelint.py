#!/usr/bin/python

"""A SubDomain lint tool.

$Id$

    Copyright (c) 2004, 2006 Novell Inc. (All rights reserved)

    This program is free software; you can redistribute it and/or
    modify it under the terms of version 2 of the GNU General Public
    License published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, contact Novell, Inc.

When called as a script, this tool will perform a variety of sanity
checks on the profiles located in the named directory, or
/etc/apparmor.d/.

Currently unmaintained and stale. :-( 
"""

import os
import sys
import dircache
import re

class Entry:
	"""Profiles are made of entries"""
	def __init__(self, string=None):
		if not string: string=""
		pname = re.compile("^(/\S+)\s+([rwxliup]+)\s*,\s*$")
		m = pname.match(string)
		if m:
			self.resource = m.group(1)
			self.right    = m.group(2)
			return
		else:
			self.resource = None
			self.right    = None
			return

class Profile:
	"""Internal representation of a profile"""
	def __init__(self, progname=None, rights=None):
		self.program = progname
		if not rights: self.rights  = []
		self.rights  = []
		return

def executables_exist(profiles):
	for profile in profiles:
		executable_exist(profile)

def executable_exist(profile):
	print profile

def parse_profiles(lines, startpoint):
	""" Given a list of lines, parse out a single profile from them,
	starting at line startpoint (inclusive), return a tuple
	(Profile, EndPoint) (exclusive!) for later use. """

	import string

	pname = re.compile("(/\S+)\s+{")
	pend  = re.compile("^\s*}")

	progname = None
	rights = []
	curline = None
	
	for i in range(startpoint, len(lines)):
		line=lines[i]
		string.strip(line)
		if not progname:
			m = pname.match(line)
			if m: progname = m.group(1)
			continue
		if progname:
			m = pend.match(line)
			if m:
				curline = i
				break
		e = Entry(line)
		if e:
			rights.extend([e])
	
	return (Profile(progname, rights), curline)
	

def main():
	"""Read in profiles, call all lint methods."""

	import getopt
	try:
		opts, args = getopt.getopt(sys.argv[1:], "vd:")
	except getopt.error, msg:
		print msg
		print "usage: %s [-v] [-d profile dir]" % sys.argv[0]
		sys.exit(1)
	pdir = "/etc/apparmor.d/"
	verbose = 0
	for o, a in opts:
		if o == '-d': pdir = a
		if o == '-v': verbose = 1
	
	if not os.path.isdir(pdir):
		print "%s: not a directory" % pdir
	
	files = []
	l = dircache.listdir(pdir)
	l = map(lambda x: os.path.join(pdir, x), l)
	l = map(lambda x: os.path.realpath(x), l)
	for f in l:
		if os.path.isfile(f):
			files.extend([f])
		elif os.path.isdir(f):
			continue
		elif not os.path.isfile(f) and verbose:
			print "%s: not a file, skipping" % f

	lines = []
	for f in files:
		lines.extend(open(f).readlines())

	profiles = []
	count = 0
	while count and count < len(lines):
		print "%d" % count
		(prof, count) = parse_profiles(lines, count)
		profiles.extend([prof])
	

	print executables_exist(profiles)
	sys.exit(0)

if __name__ == '__main__':
	exit_status = not main()
	sys.exit(exit_status)
