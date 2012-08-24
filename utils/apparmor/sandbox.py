# ------------------------------------------------------------------
#
#    Copyright (C) 2011-2012 Canonical Ltd.
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

from apparmor.common import AppArmorException, debug, error, warn, cmd
import apparmor.easyprof
import optparse
import os
import pwd
import re
import sys
import tempfile
import time

def check_requirements(binary):
    '''Verify necessary software is installed'''
    exes = ['xset',        # for detecting free X display
            'aa-easyprof', # for templates
            'aa-exec',     # for changing profile
            'sudo',        # eventually get rid of this
            binary]

    for e in exes:
        debug("Searching for '%s'" % e)
        rc, report = cmd(['which', e])
        if rc != 0:
            error("Could not find '%s'" % e, do_exit=False)
            return False

    return True

def parse_args(args=None, parser=None):
    '''Parse arguments'''
    if parser == None:
        parser = optparse.OptionParser()

    parser.add_option('-X', '--with-x',
                      dest='withx',
                      default=False,
                      help='Run in isolated X server',
                      action='store_true')
    parser.add_option('--with-xserver',
                      dest='xserver',
                      default='xpra',
                      help='Nested X server to use (default is xpra)')
    parser.add_option('-d', '--debug',
                      dest='debug',
                      default=False,
                      help='Show debug messages',
                      action='store_true')
    parser.add_option('-r', '--with-resolution',
                      dest='resolution',
                      default='640x480',
                      help='Resolution for X application')
    parser.add_option('--profile',
                      dest='profile',
                      default=None,
                      help='Specify an existing profile (see aa-status)')

    (my_opt, my_args) = parser.parse_args()
    if my_opt.debug == True:
        apparmor.common.DEBUGGING = True
    if my_opt.template == "default":
        if my_opt.withx:
            if my_opt.xserver.lower() != 'xpra' and \
               my_opt.xserver.lower() != 'xephyr':
                error("Invalid server '%s'. Use 'xpra' or 'xephyr'" % \
                      my_opt.xserver)
            my_opt.template = "sandbox-x"
        else:
            my_opt.template = "sandbox"

    return (my_opt, my_args)

def gen_policy_name(binary):
    '''Generate a temporary policy based on the binary name'''
    return "sandbox-%s%s" % (pwd.getpwuid(os.getuid())[0],
                              re.sub(r'/', '_', binary))

def aa_exec(command, opt):
    '''Execute binary under specified policy'''
    if opt.profile != None:
        policy_name = opt.profile
    else:
        opt.ensure_value("template_var", None)
        opt.ensure_value("name", None)
        opt.ensure_value("comment", None)
        opt.ensure_value("author", None)
        opt.ensure_value("copyright", None)

        binary = command[0]
        policy_name = apparmor.sandbox.gen_policy_name(binary)
        easyp = apparmor.easyprof.AppArmorEasyProfile(binary, opt)
        params = apparmor.easyprof.gen_policy_params(policy_name, opt)
        policy = easyp.gen_policy(**params)
        debug("\n%s" % policy)

        tmp = tempfile.NamedTemporaryFile(prefix = '%s-' % policy_name)
        if sys.version_info[0] >= 3:
            tmp.write(bytes(policy, 'utf-8'))
        else:
            tmp.write(policy)
        tmp.flush()

        debug("using '%s' template" % opt.template)
        # TODO: get rid of sudo
        rc, report = cmd(['sudo', 'apparmor_parser', '-r', tmp.name])
        if rc != 0:
            raise AppArmorException("Could not load policy")

    args = ['aa-exec', '-p', policy_name] + command
    rc, report = cmd(args)
    return rc, report

def run_sandbox(command, opt):
    '''Run application'''
    # aa-exec
    rc, report = aa_exec(command, opt)
    return rc, report

class SandboxXserver():
    def __init__(self, resolution, title):
        self.resolution = resolution
        self.title = title
        self.pids = []
        self.find_free_x_display()

	# TODO: for now, drop Unity's globalmenu proxy since it doesn't work
	# right in the application. (Doesn't work with firefox)
        os.environ["UBUNTU_MENUPROXY"] = ""

    def find_free_x_display(self):
        '''Find a free X display'''
        display = ""
        current = os.environ["DISPLAY"]
        for i in range(1,257): # TODO: this puts an artificial limit of 256
                               #       sandboxed applications
            tmp = ":%d" % i
            os.environ["DISPLAY"] = tmp
            rc, report = cmd(['xset', '-q'])
            if rc != 0:
                display = tmp
                break

        os.environ["DISPLAY"] = current
        if display == "":
            raise AppArmorException("Could not find available X display")

        self.display = display

    def cleanup(self):
        '''Cleanup our forked pids, etc'''
        # kill server now. It should've terminated, but be sure
        for pid in self.pids:
            os.kill(pid, 15)
            os.waitpid(pid, 0)

    def start(self):
        '''start() should be overridden'''

class SandboxXephyr(SandboxXserver):
    def start(self):
        for e in ['Xephyr', 'matchbox-window-manager']:
            debug("Searching for '%s'" % e)
            rc, report = cmd(['which', e])
            if rc != 0:
                raise AppArmorException("Could not find '%s'" % e)

        '''Start a Xephyr server'''
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
                      '-screen', self.resolution,
                      '-br',        # black background
                      '-reset',     # reset after last client exists
                      '-terminate', # terminate at server reset
                      '-title', self.title,
                      ] + x_exts + x_extra_args

            args = ['/usr/bin/Xephyr'] + x_args + [self.display]
            debug(" ".join(args))
            cmd(args)
            sys.exit(0)
        self.pids.append(listener_x)

        time.sleep(1) # FIXME: detect if running

        # Next, start the window manager
        sys.stdout.flush()
        os.chdir(os.environ["HOME"])
        listener_wm = os.fork()
        if listener_wm == 0:
            # update environment
            os.environ["DISPLAY"] = self.display
            debug("DISPLAY is now '%s'" % os.environ["DISPLAY"])

            args = ['/usr/bin/matchbox-window-manager', '-use_titlebar', 'no']
            debug(" ".join(args))
            cmd(args)
            sys.exit(0)

        self.pids.append(listener_wm)
        time.sleep(1) # FIXME: detect if running

        os.environ["DISPLAY"] = self.display

class SandboxXpra(SandboxXserver):
    def cleanup(self):
        cmd(['xpra', 'stop', self.display])
        SandboxXserver.cleanup(self)

    def start(self):
        for e in ['xpra']:
            debug("Searching for '%s'" % e)
            rc, report = cmd(['which', e])
            if rc != 0:
                raise AppArmorException("Could not find '%s'" % e)

        listener_x = os.fork()
        if listener_x == 0:
            x_args = ['--no-daemon',
                      #'--no-mmap', # for security?
                      '--no-clipboard',
                      '--no-pulseaudio']
            args = ['/usr/bin/xpra', 'start', self.display] + x_args
            debug(" ".join(args))
            cmd(args)
            sys.exit(0)
        self.pids.append(listener_x)
        time.sleep(2) # FIXME: detect if running

        # Next, attach to xpra
        sys.stdout.flush()
        os.chdir(os.environ["HOME"])
        listener_attach = os.fork()
        if listener_attach == 0:
            args = ['/usr/bin/xpra', 'attach', self.display,
                                     '--title=%s' % self.title,
                                     #'--no-mmap', # for security?
                                     '--no-clipboard',
                                     '--no-pulseaudio']
            debug(" ".join(args))
            cmd(args)
            sys.exit(0)

        self.pids.append(listener_attach)

        os.environ["DISPLAY"] = self.display
        warn("Resolution not honored in xpra")

def run_xsandbox(command, opt):
    '''Run X application in a sandbox'''
    # save environment
    old_display = os.environ["DISPLAY"]
    debug ("DISPLAY=%s" % old_display)
    old_cwd = os.getcwd()

    # first, start X
    if opt.xserver.lower() == "xephyr":
        x = SandboxXephyr(opt.resolution, command[0])
    else:
        x = SandboxXpra(opt.resolution, command[0])
    x.start()
    debug("DISPLAY is now '%s'" % os.environ["DISPLAY"])

    # aa-exec
    try:
        rc, report = aa_exec(command, opt)
    except:
        x.cleanup()
        raise
    x.cleanup()

    # reset environment
    os.chdir(old_cwd)
    os.environ["DISPLAY"] = old_display
    debug("DISPLAY is now '%s'" % os.environ["DISPLAY"])

    return rc, report
