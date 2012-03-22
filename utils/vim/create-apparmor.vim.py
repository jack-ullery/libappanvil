#!/usr/bin/python
#
#    Copyright (C) 2012 Canonical Ltd.
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
#    Written by Steve Beattie <steve@nxnw.org>, based on work by
#    Christian Boltz <apparmor@cboltz.de>

import os
import re
import subprocess
import sys

# dangerous capabilities
danger_caps=["audit_control",
             "audit_write",
             "mac_override",
             "mac_admin",
             "set_fcap",
             "sys_admin",
             "sys_module",
             "sys_rawio"]

aa_network_types=r'\s+tcp|\s+udp|\s+icmp'

aa_flags=r'(complain|audit|attach_disconnect|no_attach_disconnected|chroot_attach|chroot_no_attach|chroot_relative|namespace_relative)'

def cmd(command, input = None, stderr = subprocess.STDOUT, stdout = subprocess.PIPE, stdin = None, timeout = None):
    '''Try to execute given command (array) and return its stdout, or
    return a textual error if it failed.'''

    try:
        sp = subprocess.Popen(command, stdin=stdin, stdout=stdout, stderr=stderr, close_fds=True)
    except OSError, e:
        return [127, str(e)]

    out, outerr = sp.communicate(input)

    # Handle redirection of stdout
    if out == None:
        out = ''
    # Handle redirection of stderr
    if outerr == None:
        outerr = ''
    return [sp.returncode,out+outerr]

# get capabilities list
(rc, output) = cmd(['make', '-s', '--no-print-directory', 'list_capabilities'])
if rc != 0:
    print >>sys.stderr, ("make list_capabilities failed: " + output)
    exit(rc)

capabilities = re.sub('CAP_', '', output.strip()).lower().split(" ")
benign_caps =[]
for cap in capabilities:
    if cap not in danger_caps:
        benign_caps.append(cap)

# get network protos list
(rc, output) = cmd(['make', '-s', '--no-print-directory', 'list_af_names'])
if rc != 0:
    print >>sys.stderr, ("make list_af_names failed: " + output)
    exit(rc)

af_names = []
af_pairs = re.sub('AF_', '', output.strip()).lower().split(",")
for af_pair in af_pairs:
    af_name = af_pair.lstrip().split(" ")[0]
    # skip max af name definition
    if len(af_name) > 0 and af_name != "max":
        af_names.append(af_name)

# TODO: does a "debug" flag exist? Listed in apparmor.vim.in sdFlagKey,
# but not in aa_flags...
# -> currently (2011-01-11) not, but might come back

aa_regex_map = {
    'FILE':             r'\v^\s*(audit\s+)?(deny\s+)?(owner\s+)?(\/|\@\{\S*\})\S*\s+',
    'DENYFILE':         r'\v^\s*(audit\s+)?deny\s+(owner\s+)?(\/|\@\{\S*\})\S*\s+',
    'auditdenyowner':   r'(audit\s+)?(deny\s+)?(owner\s+)?',
    'auditdeny':        r'(audit\s+)?(deny\s+)?',
    'FILENAME':         r'(\/|\@\{\S*\})\S*',
    'EOL':              r'\s*,(\s*$|(\s*#.*$)\@=)',
    'TRANSITION':       r'(\s+-\>\s+\S+)?',
    'sdKapKey':         " ".join(benign_caps),
    'sdKapKeyDanger':   " ".join(danger_caps),
    'sdKapKeyRegex':    "|".join(capabilities),
    'sdNetworkType':    aa_network_types,
    'sdNetworkProto':   "|".join(af_names),
    'flags':            r'((flags\s*\=\s*)?\(\s*' + aa_flags + r'(\s*,\s*' + aa_flags + r')*\s*\)\s+)',
}

def my_repl(matchobj):
    #print matchobj.group(1)
    if matchobj.group(1) in aa_regex_map:
        return aa_regex_map[matchobj.group(1)]

    return matchobj.group(0)

regex = "@@(" + "|".join(aa_regex_map) + ")@@"

with file("apparmor.vim.in") as template:
    for line in template:
        line = re.sub(regex, my_repl, line.rstrip())
        print line
