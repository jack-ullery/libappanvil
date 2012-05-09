# ------------------------------------------------------------------
#
#    Copyright (C) 2011-2012 Canonical Ltd.
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

from apparmor.common import AppArmorException, debug, error, cmd
import optparse
import os
import sys
import time

global DEBUGGING

def check_requirements(binary):
    '''Verify necessary software is installed'''
    exes = ['Xephyr', 'matchbox-window-manager', binary]
    for e in exes:
        debug("Searching for '%s'" % e)
        rc, report = cmd(['which', e])
        if rc != 0:
            error("Could not find '%s'" % e, do_exit=False)
            return False
    return True

def parse_args(args=None):
    '''Parse arguments'''
    global DEBUGGING

    parser = optparse.OptionParser()
    parser.add_option('-X', '--with-x',
                      dest='withx',
                      default=False,
                      help='Run in isolated X server',
                      action='store_true')
    parser.add_option('-d', '--debug',
                      dest='debug',
                      default=False,
                      help='Show debug messages',
                      action='store_true')
    parser.add_option('-r', '--with-resolution',
                      dest='resolution',
                      default='640x480',
                      help='Resolution for X application')

    (my_opt, my_args) = parser.parse_args()
    if my_opt.debug:
        DEBUGGING = True
    return (my_opt, my_args)

def find_free_x_display():
    # TODO: detect/track and get an available display
    x_display = ":1"
    return x_display

def run_xsandbox(resolution, command):
    '''Run X application in a sandbox'''
    # Find a display to run on
    x_display = find_free_x_display()

    debug (os.environ["DISPLAY"])

    # first, start X
    listener_x = os.fork()
    if listener_x == 0:
        # TODO: break into config file? Which are needed?
        x_exts = ['-extension', 'GLX',
                  '-extension', 'MIT-SHM',
                  '-extension', 'RENDER',
                  '-extension', 'SECURITY',
                  '-extension', 'DAMAGE'
                 ]
        # verify_these
        x_extra_args = ['-host-cursor', # less secure?
                        '-fakexa',      # for games? seems not needed
                        '-nodri',       # more secure?
                       ]

        x_args = ['-nolisten', 'tcp',
                  '-screen', resolution,
                  '-br',        # black background
                  '-reset',     # reset after last client exists
                  '-terminate', # terminate at server reset
                  '-title', command[0],
                  ] + x_exts + x_extra_args

        args = ['/usr/bin/Xephyr'] + x_args + [x_display]
        debug(" ".join(args))
        sys.stderr.flush()
        os.execv(args[0], args)
        sys.exit(0)

    # save environment
    old_display = os.environ["DISPLAY"]
    old_cwd = os.getcwd()

    # update environment
    os.environ["DISPLAY"] = x_display
    debug("DISPLAY is now '%s'" % os.environ["DISPLAY"])

    time.sleep(0.2) # FIXME: detect if running

    # Next, start the window manager
    sys.stdout.flush()
    os.chdir(os.environ["HOME"])
    listener_wm = os.fork()
    if listener_wm == 0:
        args = ['/usr/bin/matchbox-window-manager', '-use_titlebar', 'no']
        debug(" ".join(args))
        sys.stderr.flush()
        os.execv(args[0], args)
        sys.exit(0)

    time.sleep(0.2) # FIXME: detect if running
    cmd(command)

    # reset environment
    os.environ["DISPLAY"] = old_display
    debug("DISPLAY is now '%s'" % os.environ["DISPLAY"])

    os.chdir(old_cwd)

    # kill server now. It should've terminated, but be sure
    cmd(['kill', '-15', "%d" % listener_wm])
    os.kill(listener_wm, 15)
    os.waitpid(listener_wm, 0)
    cmd(['kill', '-15', "%d" % listener_x])
    os.kill(listener_x, 15)
    os.waitpid(listener_x, 0)


