#!/usr/bin/env python
# ------------------------------------------------------------------
#
#   Copyright (C) 2013 Canonical Ltd.
#   Author: Steve Beattie <steve@nxnw.org>
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of version 2 of the GNU General Public
#   License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import signal
import subprocess

TIMEOUT_ERROR_CODE = 152
DEFAULT_PARSER = '../apparmor_parser'


# http://www.chiark.greenend.org.uk/ucgi/~cjwatson/blosxom/2009-07-02-python-sigpipe.html
# This is needed so that the subprocesses that produce endless output
# actually quit when the reader goes away.
def subprocess_setup():
    # Python installs a SIGPIPE handler by default. This is usually not
    # what non-Python subprocesses expect.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def run_cmd(command, input=None, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, stdin=None, timeout=120):
    '''Try to execute given command (array) and return its stdout, or
    return a textual error if it failed.'''

    try:
        sp = subprocess.Popen(command, stdin=stdin, stdout=stdout, stderr=stderr, close_fds=True, preexec_fn=subprocess_setup)
    except OSError as e:
        return [127, str(e)]

    timeout_communicate = TimeoutFunction(sp.communicate, timeout)
    out, outerr = (None, None)
    try:
        out, outerr = timeout_communicate(input)
        rc = sp.returncode
    except TimeoutFunctionException as e:
        sp.terminate()
        outerr = b'test timed out, killed'
        rc = TIMEOUT_ERROR_CODE

    # Handle redirection of stdout
    if out is None:
        out = b''
    # Handle redirection of stderr
    if outerr is None:
        outerr = b''
    return [rc, out.decode('utf-8') + outerr.decode('utf-8')]


# Timeout handler using alarm() from John P. Speno's Pythonic Avocado
class TimeoutFunctionException(Exception):
    """Exception to raise on a timeout"""
    pass


class TimeoutFunction:
    def __init__(self, function, timeout):
        self.timeout = timeout
        self.function = function

    def handle_timeout(self, signum, frame):
        raise TimeoutFunctionException()

    def __call__(self, *args, **kwargs):
        old = signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.timeout)
        try:
            result = self.function(*args, **kwargs)
        finally:
            signal.signal(signal.SIGALRM, old)
        signal.alarm(0)
        return result
