#!/usr/bin/python
import sys
import os
import re
import argparse

import apparmor.aa as apparmor

parser = argparse.ArgumentParser(description='')
parser.add_argument('--paranoid', type=str)
args = parser.parse_args()

paranoid = args.paranoid

aa_mountpoint = apparmor.check_for_apparmor()
if not aa_mountpoint:
    raise apparmor.AppArmorException(_('AppArmor seems to have not been started. Please enable AppArmor and try again.'))

pids = []
if paranoid:
    pids = list(filter(lambda x: re.search('^\d+$', x), apparmor.get_subdirectories('/proc')))
else:
    regex_tcp_udp = re.compile('^(tcp|udp)\s+\d+\s+\d+\s+\S+\:(\d+)\s+\S+\:(\*|\d+)\s+(LISTEN|\s+)\s+(\d+)\/(\S+)')
    output = apparmor.cmd(['netstat','-nlp'])[1].split('\n')
    for line in output:
        match = regex_tcp_udp.search(line)
        if match:
            pids.append(match.groups()[4])
# We can safely remove duplicate pid's?
pids = list(map(lambda x: int(x), set(pids)))

for pid in sorted(pids):
    try:
        prog = os.readlink('/proc/%s/exe'%pid)
    except:
        continue
    attr = None
    if os.path.exists('/proc/%s/attr/current'%pid):
        with apparmor.open_file_read('/proc/%s/attr/current'%pid) as current:
            for line in current:
                if line.startswith('/') or line.startswith('null'):
                    attr = line.strip()
    
    cmdline = apparmor.cmd(['cat', '/proc/%s/cmdline'%pid])[1]
    pname = cmdline.split('\0')[0]
    if '/' in pname and pname != prog:
        pname = '(%s)'%pname
    else:
        pname = ''
    if not attr:
        if re.search('^(/usr)?/bin/(python|perl|bash)', prog):
            cmdline = re.sub('\0', ' ', cmdline)
            cmdline = re.sub('\s+$', '', cmdline).strip()
            sys.stdout.write(_('%s %s (%s) not confined\n')%(pid, prog, cmdline))
        else:
            if pname and pname[-1] == ')':
                pname += ' '
            sys.stdout.write(_('%s %s %snot confined\n')%(pid, prog, pname))
    else:
        if re.search('^(/usr)?/bin/(python|perl|bash)', prog):
            cmdline = re.sub('\0', ' ', cmdline)
            cmdline = re.sub('\s+$', '', cmdline).strip()
            sys.stdout.write(_("%s %s (%s) confined by '%s'\n")%(pid, prog, cmdline, attr))
        else:
            if pname and pname[-1] == ')':
                pname += ' '
            sys.stdout.write(_("%s %s %sconfined by '%s'\n")%(pid, prog, pname, attr))

sys.exit(0)