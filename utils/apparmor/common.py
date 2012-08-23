# ------------------------------------------------------------------
#
#    Copyright (C) 2012 Canonical Ltd.
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import subprocess
import sys

DEBUGGING = False

#
# Utility classes
#
class AppArmorException(Exception):
    '''This class represents AppArmor exceptions'''
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

#
# Utility functions
#
def error(out, exit_code=1, do_exit=True):
    '''Print error message and exit'''
    try:
        print >> sys.stderr, "ERROR: %s" % (out)
    except IOError:
        pass

    if do_exit:
        sys.exit(exit_code)

def warn(out):
    '''Print warning message'''
    try:
        print >> sys.stderr, "WARN: %s" % (out)
    except IOError:
        pass

def msg(out, output=sys.stdout):
    '''Print message'''
    try:
        print >> output, "%s" % (out)
    except IOError:
        pass

def debug(out):
    '''Print debug message'''
    global DEBUGGING
    if DEBUGGING:
        try:
            print >> sys.stderr, "DEBUG: %s" % (out)
        except IOError:
            pass

def cmd(command):
    '''Try to execute the given command.'''
    debug(command)
    try:
        sp = subprocess.Popen(command, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
    except OSError, ex:
        return [127, str(ex)]

    out = sp.communicate()[0]
    return [sp.returncode, out]

def cmd_pipe(command1, command2):
    '''Try to pipe command1 into command2.'''
    try:
        sp1 = subprocess.Popen(command1, stdout=subprocess.PIPE)
        sp2 = subprocess.Popen(command2, stdin=sp1.stdout)
    except OSError, ex:
        return [127, str(ex)]

    out = sp2.communicate()[0]
    return [sp2.returncode, out]

