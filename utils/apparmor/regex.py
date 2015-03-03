# ----------------------------------------------------------------------
#    Copyright (C) 2013 Kshitij Gupta <kgupta8592@gmail.com>
#    Copyright (C) 2014 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
# ----------------------------------------------------------------------

import re

## Profile parsing Regex
RE_AUDIT_DENY           = '^\s*(?P<audit>audit\s+)?(?P<allow>allow\s+|deny\s+)?'  # line start, optionally: leading whitespace, <audit> and <allow>/deny
RE_OWNER                = '(?P<owner>owner\s+)?'  # optionally: <owner>
RE_EOL                  = '\s*(?P<comment>#.*?)?\s*$'  # optional whitespace, optional <comment>, optional whitespace, end of the line
RE_COMMA_EOL            = '\s*,' + RE_EOL # optional whitespace, comma + RE_EOL

RE_PROFILE_START        = re.compile('^\s*("?(/.+?)"??|(profile\s+"?(.+?)"??))\s+((flags=)?\((.+)\)\s+)?\{' + RE_EOL)
RE_PROFILE_END          = re.compile('^\s*\}' + RE_EOL)
RE_PROFILE_CAP          = re.compile(RE_AUDIT_DENY + 'capability(?P<capability>(\s+\S+)+)?' + RE_COMMA_EOL)
RE_PROFILE_LINK         = re.compile(RE_AUDIT_DENY + 'link\s+(((subset)|(<=))\s+)?([\"\@\/].*?"??)\s+->\s*([\"\@\/].*?"??)' + RE_COMMA_EOL)
RE_PROFILE_CHANGE_PROFILE = re.compile('^\s*change_profile\s+->\s*("??.+?"??)' + RE_COMMA_EOL)
RE_PROFILE_ALIAS        = re.compile('^\s*alias\s+("??.+?"??)\s+->\s*("??.+?"??)' + RE_COMMA_EOL)
RE_PROFILE_RLIMIT       = re.compile('^\s*set\s+rlimit\s+(.+)\s+(<=)?\s*(.+)' + RE_COMMA_EOL)
RE_PROFILE_BOOLEAN      = re.compile('^\s*(\$\{?\w*\}?)\s*=\s*(true|false)\s*,?' + RE_EOL, flags=re.IGNORECASE)
RE_PROFILE_VARIABLE     = re.compile('^\s*(@\{?\w+\}?)\s*(\+?=)\s*(@*.+?)\s*,?' + RE_EOL)
RE_PROFILE_CONDITIONAL  = re.compile('^\s*if\s+(not\s+)?(\$\{?\w*\}?)\s*\{' + RE_EOL)
RE_PROFILE_CONDITIONAL_VARIABLE = re.compile('^\s*if\s+(not\s+)?defined\s+(@\{?\w+\}?)\s*\{\s*(#.*)?$')
RE_PROFILE_CONDITIONAL_BOOLEAN = re.compile('^\s*if\s+(not\s+)?defined\s+(\$\{?\w+\}?)\s*\{\s*(#.*)?$')
RE_PROFILE_BARE_FILE_ENTRY = re.compile(RE_AUDIT_DENY + RE_OWNER + 'file' + RE_COMMA_EOL)
RE_PROFILE_PATH_ENTRY   = re.compile(RE_AUDIT_DENY + RE_OWNER + '(file\s+)?([\"@/].*?)\s+(\S+)(\s+->\s*(.*?))?' + RE_COMMA_EOL)
RE_PROFILE_NETWORK      = re.compile(RE_AUDIT_DENY + 'network(.*)' + RE_EOL)
RE_NETWORK_FAMILY_TYPE = re.compile('\s+(\S+)\s+(\S+)\s*,$')
RE_NETWORK_FAMILY = re.compile('\s+(\S+)\s*,$')
RE_PROFILE_CHANGE_HAT   = re.compile('^\s*\^(\"??.+?\"??)' + RE_COMMA_EOL)
RE_PROFILE_HAT_DEF      = re.compile('^\s*(\^|hat\s+)(?P<hat>\"??.+?\"??)\s+((flags=)?\((?P<flags>.+)\)\s+)*\{' + RE_EOL)
RE_PROFILE_DBUS         = re.compile(RE_AUDIT_DENY + '(dbus\s*,|dbus\s+[^#]*\s*,)' + RE_EOL)
RE_PROFILE_MOUNT        = re.compile(RE_AUDIT_DENY + '((mount|remount|umount|unmount)(\s+[^#]*)?\s*,)' + RE_EOL)
RE_PROFILE_SIGNAL       = re.compile(RE_AUDIT_DENY + '(signal\s*,|signal\s+[^#]*\s*,)' + RE_EOL)
RE_PROFILE_PTRACE       = re.compile(RE_AUDIT_DENY + '(ptrace\s*,|ptrace\s+[^#]*\s*,)' + RE_EOL)
RE_PROFILE_PIVOT_ROOT   = re.compile(RE_AUDIT_DENY + '(pivot_root\s*,|pivot_root\s+[^#]*\s*,)' + RE_EOL)
RE_PROFILE_UNIX         = re.compile(RE_AUDIT_DENY + '(unix\s*,|unix\s+[^#]*\s*,)' + RE_EOL)

# match anything that's not " or #, or matching quotes with anything except quotes inside
__re_no_or_quoted_hash = '([^#"]|"[^"]*")*'

RE_RULE_HAS_COMMA = re.compile('^' + __re_no_or_quoted_hash +
    ',\s*(#.*)?$')  # match comma plus any trailing comment
RE_HAS_COMMENT_SPLIT = re.compile('^(?P<not_comment>' + __re_no_or_quoted_hash + ')' + # store in 'not_comment' group
    '(?P<comment>#.*)$')  # match trailing comment and store in 'comment' group


def strip_quotes(data):
    if data[0] + data[-1] == '""':
        return data[1:-1]
    else:
        return data
