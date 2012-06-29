# ------------------------------------------------------------------
#
#    Copyright (C) 2011-2012 Canonical Ltd.
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

from __future__ import with_statement

import codecs
import glob
import optparse
import os
import re
import subprocess
import sys
import tempfile

#
# TODO: move this out to the common library
#
#from apparmor import AppArmorException
class AppArmorException(Exception):
    '''This class represents AppArmor exceptions'''
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)
#
# End common
#

DEBUGGING = False

#
# TODO: move this out to a utilities library
#
def error(out, exit_code=1, do_exit=True):
    '''Print error message and exit'''
    try:
        sys.stderr.write("ERROR: %s\n" % (out))
    except IOError:
        pass

    if do_exit:
        sys.exit(exit_code)


def warn(out):
    '''Print warning message'''
    try:
        sys.stderr.write("WARN: %s\n" % (out))
    except IOError:
        pass


def msg(out, output=sys.stdout):
    '''Print message'''
    try:
        sys.stdout.write("%s\n" % (out))
    except IOError:
        pass


def cmd(command):
    '''Try to execute the given command.'''
    debug(command)
    try:
        sp = subprocess.Popen(command, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
    except OSError as ex:
        return [127, str(ex)]

    out = sp.communicate()[0]
    return [sp.returncode, out]


def cmd_pipe(command1, command2):
    '''Try to pipe command1 into command2.'''
    try:
        sp1 = subprocess.Popen(command1, stdout=subprocess.PIPE)
        sp2 = subprocess.Popen(command2, stdin=sp1.stdout)
    except OSError as ex:
        return [127, str(ex)]

    out = sp2.communicate()[0]
    return [sp2.returncode, out]


def debug(out):
    '''Print debug message'''
    if DEBUGGING:
        try:
            sys.stderr.write("DEBUG: %s\n" % (out))
        except IOError:
            pass


def valid_binary_path(path):
    '''Validate name'''
    try:
        a_path = os.path.abspath(path)
    except Exception:
        debug("Could not find absolute path for binary")
        return False

    if path != a_path:
        debug("Binary should use a normalized absolute path")
        return False

    if not os.path.exists(a_path):
        return True

    r_path = os.path.realpath(path)
    if r_path != a_path:
        debug("Binary should not be a symlink")
        return False

    return True


def valid_variable_name(var):
    '''Validate variable name'''
    if re.search(r'[a-zA-Z0-9_]+$', var):
        return True
    return False


def valid_path(path):
    '''Valid path'''
    # No relative paths
    m = "Invalid path: %s" % (path)
    if not path.startswith('/'):
        debug("%s (relative)" % (m))
        return False

    try:
        os.path.normpath(path)
    except Exception:
        debug("%s (could not normalize)" % (m))
        return False
    return True


def get_directory_contents(path):
    '''Find contents of the given directory'''
    if not valid_path(path):
        return None

    files = []
    for f in glob.glob(path + "/*"):
        files.append(f)

    files.sort()
    return files

def open_file_read(path):
    '''Open specified file read-only'''
    try:
        orig = codecs.open(path, 'r', "UTF-8")
    except Exception:
        raise

    return orig


def verify_policy(policy):
    '''Verify policy compiles'''
    exe = "/sbin/apparmor_parser"
    if not os.path.exists(exe):
        rc, exe = cmd(['which', 'apparmor_parser'])
        if rc != 0:
            warn("Could not find apparmor_parser. Skipping verify")
            return True

    fn = ""
    # if policy starts with '/' and is one line, assume it is a path
    if len(policy.splitlines()) == 1 and valid_path(policy):
        fn = policy
    else:
        f, fn = tempfile.mkstemp(prefix='aa-easyprof')
        if not isinstance(policy, bytes):
            policy = policy.encode('utf-8')
        os.write(f, policy)
        os.close(f)

    rc, out = cmd([exe, '-p', fn])
    os.unlink(fn)
    if rc == 0:
        return True
    return False

#
# End utility functions
#


class AppArmorEasyProfile:
    '''Easy profile class'''
    def __init__(self, binary, opt):
        self.conffile = "/etc/apparmor/easyprof.conf"
        if opt.conffile:
            self.conffile = os.path.abspath(opt.conffile)

        self.dirs = dict()
        if os.path.isfile(self.conffile):
            self._get_defaults()

        if opt.templates_dir and os.path.isdir(opt.templates_dir):
            self.dirs['templates'] = os.path.abspath(opt.templates_dir)
        elif not opt.templates_dir and \
             opt.template and \
             os.path.isfile(opt.template) and \
             valid_path(opt.template):
	    # If we specified the template and it is an absolute path, just set
	    # the templates directory to the parent of the template so we don't
            # have to require --template-dir with absolute paths.
            self.dirs['templates'] = os.path.abspath(os.path.dirname(opt.template))
        if opt.policy_groups_dir and os.path.isdir(opt.policy_groups_dir):
            self.dirs['policygroups'] = os.path.abspath(opt.policy_groups_dir)

        if not 'templates' in self.dirs:
            raise AppArmorException("Could not find templates directory")
        if not 'policygroups' in self.dirs:
            raise AppArmorException("Could not find policygroups directory")

        self.aa_topdir = "/etc/apparmor.d"

        self.binary = binary
        if binary != None:
            if not valid_binary_path(binary):
                raise AppArmorException("Invalid path for binary: '%s'" % binary)

        self.set_template(opt.template)
        self.set_policygroup(opt.policy_groups)
        if opt.name:
            self.set_name(opt.name)
        elif self.binary != None:
            self.set_name(self.binary)

        self.templates = get_directory_contents(self.dirs['templates'])
        self.policy_groups = get_directory_contents(self.dirs['policygroups'])

    def _get_defaults(self):
        '''Read in defaults from configuration'''
        if not os.path.exists(self.conffile):
            raise AppArmorException("Could not find '%s'" % self.conffile)

        # Read in the configuration
        f = open_file_read(self.conffile)

        pat = re.compile(r'^\w+=".*"?')
        for line in f:
            if not pat.search(line):
                continue
            if line.startswith("POLICYGROUPS_DIR="):
                d = re.split(r'=', line.strip())[1].strip('["\']')
                self.dirs['policygroups'] = d
            elif line.startswith("TEMPLATES_DIR="):
                d = re.split(r'=', line.strip())[1].strip('["\']')
                self.dirs['templates'] = d
        f.close()

        keys = self.dirs.keys()
        if 'templates' not in keys:
            raise AppArmorException("Could not find TEMPLATES_DIR in '%s'" % self.conffile)
        if 'policygroups' not in keys:
            raise AppArmorException("Could not find POLICYGROUPS_DIR in '%s'" % self.conffile)

        for k in self.dirs.keys():
            if not os.path.isdir(self.dirs[k]):
                raise AppArmorException("Could not find '%s'" % self.dirs[k])

    def set_name(self, name):
        '''Set name of policy'''
        self.name = name

    def get_template(self):
        '''Get contents of current template'''
        return open(self.template).read()

    def set_template(self, template):
        '''Set current template'''
        self.template = template
        if not template.startswith('/'):
            self.template = os.path.join(self.dirs['templates'], template)
        if not os.path.exists(self.template):
            raise AppArmorException('%s does not exist' % (self.template))

    def get_templates(self):
        '''Get list of all available templates by filename'''
        return self.templates

    def get_policygroup(self, policygroup):
        '''Get contents of specific policygroup'''
        p = policygroup
        if not p.startswith('/'):
            p = os.path.join(self.dirs['policygroups'], p)
        if self.policy_groups == None or not p in self.policy_groups:
            raise AppArmorException("Policy group '%s' does not exist" % p)
        return open(p).read()

    def set_policygroup(self, policygroups):
        '''Set policygroups'''
        self.policy_groups = []
        if policygroups != None:
            for p in policygroups.split(','):
                if not p.startswith('/'):
                    p = os.path.join(self.dirs['policygroups'], p)
                if not os.path.exists(p):
                    raise AppArmorException('%s does not exist' % (p))
                self.policy_groups.append(p)

    def get_policy_groups(self):
        '''Get list of all policy groups by filename'''
        return self.policy_groups

    def gen_abstraction_rule(self, abstraction):
        '''Generate an abstraction rule'''
        p = os.path.join(self.aa_topdir, "abstractions", abstraction)
        if not os.path.exists(p):
            raise AppArmorException("%s does not exist" % p)
        return "#include <abstractions/%s>" % abstraction

    def gen_variable_declaration(self, dec):
        '''Generate a variable declaration'''
        if not re.search(r'^@\{[a-zA-Z_]+\}=.+', dec):
            raise AppArmorException("Invalid variable declaration '%s'" % dec)
        return dec

    def gen_path_rule(self, path, access):
        rule = []
        if not path.startswith('/') and not path.startswith('@'):
            raise AppArmorException("'%s' should not be relative path" % path)

        owner = ""
        if path.startswith('/home/') or path.startswith("@{HOME"):
            owner = "owner "

        if path.endswith('/'):
            rule.append("%s %s," % (path, access))
            rule.append("%s%s** %s," % (owner, path, access))
        elif path.endswith('/**') or path.endswith('/*'):
            rule.append("%s %s," % (os.path.dirname(path), access))
            rule.append("%s%s %s," % (owner, path, access))
        else:
            rule.append("%s%s %s," % (owner, path, access))

        return rule


    def gen_policy(self, name, binary, template_var=[], abstractions=None, policy_groups=None, read_path=[], write_path=[], author=None, comment=None, copyright=None):
        def find_prefix(t, s):
            '''Calculate whitespace prefix based on occurrence of s in t'''
            pat = re.compile(r'^ *%s' % s)
            p = ""
            for line in t.splitlines():
                if pat.match(line):
                    p = " " * (len(line) - len(line.lstrip()))
                    break
            return p

        policy = self.get_template()
        if '###ENDUSAGE###' in policy:
            found = False
            tmp = ""
            for line in policy.splitlines():
                if not found:
                    if line.startswith('###ENDUSAGE###'):
                        found = True
                    continue
                tmp += line + "\n"
            policy = tmp

        # Fill-in profile name and binary
        policy = re.sub(r'###NAME###', name, policy)
        policy = re.sub(r'###BINARY###', binary, policy)

        # Fill-in various comment fields
        if comment != None:
            policy = re.sub(r'###COMMENT###', "Comment: %s" % comment, policy)

        if author != None:
            policy = re.sub(r'###AUTHOR###', "Author: %s" % author, policy)

        if copyright != None:
            policy = re.sub(r'###COPYRIGHT###', "Copyright: %s" % copyright, policy)

        # Fill-in rules and variables with proper indenting
        search = '###ABSTRACTIONS###'
        prefix = find_prefix(policy, search)
        s = "%s# No abstractions specified" % prefix
        if abstractions != None:
            s = "%s# Specified abstractions" % (prefix)
            for i in abstractions.split(','):
                s += "\n%s%s" % (prefix, self.gen_abstraction_rule(i))
        policy = re.sub(r' *%s' % search, s, policy)

        search = '###POLICYGROUPS###'
        prefix = find_prefix(policy, search)
        s = "%s# No policy groups specified" % prefix
        if policy_groups != None:
            s = "%s# Rules specified via policy groups" % (prefix)
            for i in policy_groups.split(','):
                for line in self.get_policygroup(i).splitlines():
                    s += "\n%s%s" % (prefix, line)
                if i != policy_groups.split(',')[-1]:
                    s += "\n"
        policy = re.sub(r' *%s' % search, s, policy)

        search = '###VAR###'
        prefix = find_prefix(policy, search)
        s = "%s# No template variables specified" % prefix
        if len(template_var) > 0:
            s = "%s# Specified profile variables" % (prefix)
            for i in template_var:
                s += "\n%s%s" % (prefix, self.gen_variable_declaration(i))
        policy = re.sub(r' *%s' % search, s, policy)

        search = '###READS###'
        prefix = find_prefix(policy, search)
        s = "%s# No read paths specified" % prefix
        if len(read_path) > 0:
            s = "%s# Specified read permissions" % (prefix)
            for i in read_path:
                for r in self.gen_path_rule(i, 'r'):
                    s += "\n%s%s" % (prefix, r)
        policy = re.sub(r' *%s' % search, s, policy)

        search = '###WRITES###'
        prefix = find_prefix(policy, search)
        s = "%s# No write paths specified" % prefix
        if len(write_path) > 0:
            s = "%s# Specified write permissions" % (prefix)
            for i in write_path:
                for r in self.gen_path_rule(i, 'rwk'):
                    s += "\n%s%s" % (prefix, r)
        policy = re.sub(r' *%s' % search, s, policy)

        if not verify_policy(policy):
            debug("\n" + policy)
            raise AppArmorException("Invalid policy")

        return policy

def print_basefilenames(files):
    for i in files:
        sys.stdout.write("%s\n" % (os.path.basename(i)))

def print_files(files):
    for i in files:
        with open(i) as f:
            sys.stdout.write(f.read()+"\n")

def parse_args(args=None):
    '''Parse arguments'''
    global DEBUGGING

    parser = optparse.OptionParser()
    parser.add_option("-c", "--config-file",
                      dest="conffile",
                      help="Use alternate configuration file",
                      metavar="FILE")
    parser.add_option("-d", "--debug",
                      help="Show debugging output",
                      action='store_true',
                      default=False)
    parser.add_option("-t", "--template",
                      dest="template",
                      help="Use non-default policy template",
                      metavar="TEMPLATE",
                      default='default')
    parser.add_option("--list-templates",
                      help="List available templates",
                      action='store_true',
                      default=False)
    parser.add_option("--templates-dir",
                      dest="templates_dir",
                      help="Use non-default templates directory",
                      metavar="DIR")
    parser.add_option("--show-template",
                      help="Show specified template",
                      action='store_true',
                      default=False)
    parser.add_option("-p", "--policy-groups",
                      help="Comma-separated list of policy groups",
                      metavar="POLICYGROUPS")
    parser.add_option("--list-policy-groups",
                      help="List available policy groups",
                      action='store_true',
                      default=False)
    parser.add_option("--policy-groups-dir",
                      dest="policy_groups_dir",
                      help="Use non-default policy-groups directory",
                      metavar="DIR")
    parser.add_option("--show-policy-group",
                      help="Show specified policy groups",
                      action='store_true',
                      default=False)
    parser.add_option("-a", "--abstractions",
                      dest="abstractions",
                      help="Comma-separated list of abstractions",
                      metavar="ABSTRACTIONS")
    parser.add_option("--read-path",
                      dest="read_path",
                      help="Path allowing owner reads",
                      metavar="PATH",
                      action="append")
    parser.add_option("--write-path",
                      dest="write_path",
                      help="Path allowing owner writes",
                      metavar="PATH",
                      action="append")
    parser.add_option("-n", "--name",
                      dest="name",
                      help="Name of policy",
                      metavar="NAME")
    parser.add_option("--comment",
                      dest="comment",
                      help="Comment for policy",
                      metavar="COMMENT")
    parser.add_option("--author",
                      dest="author",
                      help="Author of policy",
                      metavar="COMMENT")
    parser.add_option("--copyright",
                      dest="copyright",
                      help="Copyright for policy",
                      metavar="COMMENT")
    parser.add_option("--template-var",
                      dest="template_var",
                      help="Declare AppArmor variable",
                      metavar="@{VARIABLE}=VALUE",
                      action="append")

    (my_opt, my_args) = parser.parse_args(args)
    if my_opt.debug:
        DEBUGGING = True
    return (my_opt, my_args)

def gen_policy_params(binary, opt):
    '''Generate parameters for gen_policy'''
    params = dict(binary=binary)
    if opt.name:
        params['name'] = opt.name
    else:
        params['name'] = os.path.basename(binary)
    if opt.template_var: # What about specified multiple times?
        params['template_var'] = opt.template_var
    if opt.abstractions:
        params['abstractions'] = opt.abstractions
    if opt.policy_groups:
        params['policy_groups'] = opt.policy_groups
    if opt.read_path:
        params['read_path'] = opt.read_path
    if opt.write_path:
        params['write_path'] = opt.write_path
    if opt.abstractions:
        params['abstractions'] = opt.abstractions
    if opt.comment:
        params['comment'] = opt.comment
    if opt.author:
        params['author'] = opt.author
    if opt.copyright:
        params['copyright'] = opt.copyright

    return params

