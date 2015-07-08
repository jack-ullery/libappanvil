# ------------------------------------------------------------------
#
#    Copyright (C) 2015 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import cgitb
import os
import sys
import tempfile
import traceback

#
# Exception handling
#
def handle_exception(*exc_info):
    '''Used as exception handler in the aa-* tools.
       For AppArmorException (used for profile syntax errors etc.), print only the exceptions
       value because a backtrace is superfluous and would confuse users.
       For other exceptions, print backtrace and save detailed information in a file in /tmp/
       (including variable content etc.) to make debugging easier.
    '''
    (ex_cls, ex, tb) = exc_info

    if ex_cls.__name__  == 'AppArmorException':  # I didn't find a way to get this working with isinstance() :-/
        print('')
        print(ex.value)
    else:
        (fd, path) = tempfile.mkstemp(prefix='apparmor-bugreport-', suffix='.txt')
        file = os.fdopen(fd, 'w')
        #file = open_file_write(path)  # writes everything converted to utf8 - not sure if we want this...

        cgitb_hook = cgitb.Hook(display=1, file=file, format='text', context=10)
        cgitb_hook.handle(exc_info)

        file.write('Please consider reporting a bug at https://bugs.launchpad.net/apparmor/\n')
        file.write('and attach this file.\n')

        print(''.join(traceback.format_exception(*exc_info)))
        print('')
        print('An unexpected error occoured!')
        print('')
        print('For details, see %s' % path)
        print('Please consider reporting a bug at https://bugs.launchpad.net/apparmor/')
        print('and attach this file.')

def enable_aa_exception_handler():
    '''Setup handle_exception() as exception handler'''
    sys.excepthook = handle_exception
