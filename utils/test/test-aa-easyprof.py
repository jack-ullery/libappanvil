#! /usr/bin/env python
# ------------------------------------------------------------------
#
#    Copyright (C) 2011-2012 Canonical Ltd.
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import glob
import os
import shutil
import sys
import tempfile
import unittest

topdir = None
debugging = False

def recursive_rm(dirPath, contents_only=False):
    '''recursively remove directory'''
    names = os.listdir(dirPath)
    for name in names:
        path = os.path.join(dirPath, name)
        if os.path.islink(path) or not os.path.isdir(path):
            os.unlink(path)
        else:
            recursive_rm(path)
    if contents_only == False:
        os.rmdir(dirPath)

#
# Our test class
#
class T(unittest.TestCase):
    def setUp(self):
        '''Setup for tests'''
        global topdir

        self.tmpdir = tempfile.mkdtemp(prefix='test-aa-easyprof')

        # Copy everything into place
        for d in ['easyprof/policygroups', 'easyprof/templates']:
            shutil.copytree(os.path.join(topdir, d), os.path.join(self.tmpdir, os.path.basename(d)))

        # Create a test template
        self.test_template = "test-template"
        contents = '''# vim:syntax=apparmor
# %s
# AppArmor policy for ###NAME###
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

###VAR###

###BINARY### {
  #include <abstractions/base>

  ###ABSTRACTIONS###

  ###POLICYGROUPS###

  ###READS###

  ###WRITES###
}

''' % (self.test_template)
        open(os.path.join(self.tmpdir, 'templates', self.test_template), 'w').write(contents)

        # Create a test policygroup
        self.test_policygroup = "test-policygroup"
        contents = '''
  # %s
  #include <abstractions/gnome>
  #include <abstractions/nameservice>
''' % (self.test_policygroup)
        open(os.path.join(self.tmpdir, 'policygroups', self.test_policygroup), 'w').write(contents)

        # setup our conffile
        self.conffile = os.path.join(self.tmpdir, 'easyprof.conf')
        contents = '''
POLICYGROUPS_DIR="%s/policygroups"
TEMPLATES_DIR="%s/templates"
''' % (self.tmpdir, self.tmpdir)
        open(self.conffile, 'w').write(contents)

        self.binary = "/opt/bin/foo"
        self.full_args = ['-c', self.conffile, self.binary]

        if debugging:
            self.full_args.append('-d')

        (self.options, self.args) = easyprof.parse_args(self.full_args + [self.binary])

    def tearDown(self):
        '''Teardown for tests'''
        if os.path.exists(self.tmpdir):
            sys.stdout.write("%s\n" % self.tmpdir)
            recursive_rm(self.tmpdir)

#
# config file tests
#
    def test_configuration_file_p_invalid(self):
        '''Test config parsing (invalid POLICYGROUPS_DIR)'''
        contents = '''
POLICYGROUPS_DIR=
TEMPLATES_DIR="%s/templates"
''' % (self.tmpdir)

        open(self.conffile, 'w').write(contents)
        try:
            easyprof.AppArmorEasyProfile(self.binary, self.options)
        except easyprof.AppArmorException:
            return
        except Exception:
            raise

        raise Exception ("File should have been invalid")

    def test_configuration_file_p_empty(self):
        '''Test config parsing (empty POLICYGROUPS_DIR)'''
        contents = '''
POLICYGROUPS_DIR="%s"
TEMPLATES_DIR="%s/templates"
''' % ('', self.tmpdir)

        open(self.conffile, 'w').write(contents)
        try:
            easyprof.AppArmorEasyProfile(self.binary, self.options)
        except easyprof.AppArmorException:
            return
        except Exception:
            raise

        raise Exception ("File should have been invalid")

    def test_configuration_file_p_nonexistent(self):
        '''Test config parsing (nonexistent POLICYGROUPS_DIR)'''
        contents = '''
POLICYGROUPS_DIR="%s/policygroups"
TEMPLATES_DIR="%s/templates"
''' % ('/nonexistent', self.tmpdir)

        open(self.conffile, 'w').write(contents)
        try:
            easyprof.AppArmorEasyProfile(self.binary, self.options)
        except easyprof.AppArmorException:
            return
        except Exception:
            raise

        raise Exception ("File should have been invalid")

    def test_policygroups_dir_relative(self):
        '''Test --policy-groups-dir (relative DIR)'''
        os.chdir(self.tmpdir)
        rel = os.path.join(self.tmpdir, 'relative')
        os.mkdir(rel)
        shutil.copy(os.path.join(self.tmpdir, 'policygroups', self.test_policygroup), os.path.join(rel, self.test_policygroup))

        args = self.full_args
        args += ['--policy-groups-dir', './relative', '--show-policy-group', '--policy-groups=%s' % self.test_policygroup]
        (self.options, self.args) = easyprof.parse_args(args)
        easyp = easyprof.AppArmorEasyProfile(self.binary, self.options)

        # no fallback
        self.assertTrue(easyp.dirs['policygroups'] == rel, "Not using specified --policy-groups-dir")
        self.assertFalse(easyp.get_policy_groups() == None, "Could not find policy-groups")

    def test_policygroups_dir_nonexistent(self):
        '''Test --policy-groups-dir (nonexistent DIR)'''
        os.chdir(self.tmpdir)
        rel = os.path.join(self.tmpdir, 'nonexistent')

        args = self.full_args
        args += ['--policy-groups-dir', rel, '--show-policy-group', '--policy-groups=%s' % self.test_policygroup]
        (self.options, self.args) = easyprof.parse_args(args)
        easyp = easyprof.AppArmorEasyProfile(self.binary, self.options)

        # test if using fallback
        self.assertFalse(easyp.dirs['policygroups'] == rel, "Using nonexistent --policy-groups-dir")

        # test fallback
        self.assertTrue(easyp.get_policy_groups() != None, "Found policy-groups when shouldn't have")

    def test_policygroups_dir_valid(self):
        '''Test --policy-groups-dir (valid DIR)'''
        os.chdir(self.tmpdir)
        valid = os.path.join(self.tmpdir, 'valid')
        os.mkdir(valid)
        shutil.copy(os.path.join(self.tmpdir, 'policygroups', self.test_policygroup), os.path.join(valid, self.test_policygroup))

        args = self.full_args
        args += ['--policy-groups-dir', valid, '--show-policy-group', '--policy-groups=%s' % self.test_policygroup]
        (self.options, self.args) = easyprof.parse_args(args)
        easyp = easyprof.AppArmorEasyProfile(self.binary, self.options)

        # no fallback
        self.assertTrue(easyp.dirs['policygroups'] == valid, "Not using specified --policy-groups-dir")
        self.assertFalse(easyp.get_policy_groups() == None, "Could not find policy-groups")

    def test_configuration_file_t_invalid(self):
        '''Test config parsing (invalid TEMPLATES_DIR)'''
        contents = '''
TEMPLATES_DIR=
POLICYGROUPS_DIR="%s/templates"
''' % (self.tmpdir)

        open(self.conffile, 'w').write(contents)
        try:
            easyprof.AppArmorEasyProfile(self.binary, self.options)
        except easyprof.AppArmorException:
            return
        except Exception:
            raise

        raise Exception ("File should have been invalid")

    def test_configuration_file_t_empty(self):
        '''Test config parsing (empty TEMPLATES_DIR)'''
        contents = '''
TEMPLATES_DIR="%s"
POLICYGROUPS_DIR="%s/templates"
''' % ('', self.tmpdir)

        open(self.conffile, 'w').write(contents)
        try:
            easyprof.AppArmorEasyProfile(self.binary, self.options)
        except easyprof.AppArmorException:
            return
        except Exception:
            raise

        raise Exception ("File should have been invalid")

    def test_configuration_file_t_nonexistent(self):
        '''Test config parsing (nonexistent TEMPLATES_DIR)'''
        contents = '''
TEMPLATES_DIR="%s/policygroups"
POLICYGROUPS_DIR="%s/templates"
''' % ('/nonexistent', self.tmpdir)

        open(self.conffile, 'w').write(contents)
        try:
            easyprof.AppArmorEasyProfile(self.binary, self.options)
        except easyprof.AppArmorException:
            return
        except Exception:
            raise

        raise Exception ("File should have been invalid")

    def test_templates_dir_relative(self):
        '''Test --templates-dir (relative DIR)'''
        os.chdir(self.tmpdir)
        rel = os.path.join(self.tmpdir, 'relative')
        os.mkdir(rel)
        shutil.copy(os.path.join(self.tmpdir, 'templates', self.test_template), os.path.join(rel, self.test_template))

        args = self.full_args
        args += ['--templates-dir', './relative', '--show-template', '--template=%s' % self.test_template]
        (self.options, self.args) = easyprof.parse_args(args)
        easyp = easyprof.AppArmorEasyProfile(self.binary, self.options)

        # no fallback
        self.assertTrue(easyp.dirs['templates'] == rel, "Not using specified --template-dir")
        self.assertFalse(easyp.get_templates() == None, "Could not find templates")

    def test_templates_dir_nonexistent(self):
        '''Test --templates-dir (nonexistent DIR)'''
        os.chdir(self.tmpdir)
        rel = os.path.join(self.tmpdir, 'nonexistent')

        args = self.full_args
        args += ['--templates-dir', rel, '--show-template', '--template=%s' % self.test_template]
        (self.options, self.args) = easyprof.parse_args(args)
        easyp = easyprof.AppArmorEasyProfile(self.binary, self.options)

        # test if using fallback
        self.assertFalse(easyp.dirs['templates'] == rel, "Using nonexistent --template-dir")

        # test fallback
        self.assertTrue(easyp.get_templates() != None, "Found templates when shouldn't have")

    def test_templates_dir_valid(self):
        '''Test --templates-dir (valid DIR)'''
        os.chdir(self.tmpdir)
        valid = os.path.join(self.tmpdir, 'valid')
        os.mkdir(valid)
        shutil.copy(os.path.join(self.tmpdir, 'templates', self.test_template), os.path.join(valid, self.test_template))

        args = self.full_args
        args += ['--templates-dir', valid, '--show-template', '--template=%s' % self.test_template]
        (self.options, self.args) = easyprof.parse_args(args)
        easyp = easyprof.AppArmorEasyProfile(self.binary, self.options)

        # no fallback
        self.assertTrue(easyp.dirs['templates'] == valid, "Not using specified --template-dir")
        self.assertFalse(easyp.get_templates() == None, "Could not find templates")

#
# Binary file tests
#
    def test_binary(self):
        '''Test binary'''
        easyprof.AppArmorEasyProfile('/bin/ls', self.options)

    def test_binary_nonexistent(self):
        '''Test binary (nonexistent)'''
        easyprof.AppArmorEasyProfile(os.path.join(self.tmpdir, 'nonexistent'), self.options)

    def test_binary_relative(self):
        '''Test binary (relative)'''
        try:
            easyprof.AppArmorEasyProfile('./foo', self.options)
        except easyprof.AppArmorException:
            return
        except Exception:
            raise
        raise Exception ("Binary should have been invalid")

    def test_binary_symlink(self):
        '''Test binary (symlink)'''
        exe = os.path.join(self.tmpdir, 'exe')
        open(exe, 'a').close()
        symlink = exe + ".lnk"
        os.symlink(exe, symlink)

        try:
            easyprof.AppArmorEasyProfile(symlink, self.options)
        except easyprof.AppArmorException:
            return
        except Exception:
            raise
        raise Exception ("Binary should have been invalid")

#
# Templates tests
#
    def test_templates_list(self):
        '''Test templates (list)'''
        args = self.full_args
        args.append('--list-templates')
        (self.options, self.args) = easyprof.parse_args(args)

        easyp = easyprof.AppArmorEasyProfile(None, self.options)
        for i in easyp.get_templates():
            self.assertTrue(os.path.exists(i), "Could not find '%s'" % i)

    def test_templates_show(self):
        '''Test templates (show)'''
        files = []
        for f in glob.glob("%s/templates/*" % self.tmpdir):
            files.append(f)

        for f in files:
            args = self.full_args
            args += ['--show-template', '--template', f]
            (self.options, self.args) = easyprof.parse_args(args)
            easyp = easyprof.AppArmorEasyProfile(None, self.options)

            path = os.path.join(easyp.dirs['templates'], f)
            self.assertTrue(os.path.exists(path), "Could not find '%s'" % path)
            open(path).read()

#
# Policygroups tests
#
    def test_policygroups_list(self):
        '''Test policygroups (list)'''
        args = self.full_args
        args.append('--list-policy-groups')
        (self.options, self.args) = easyprof.parse_args(args)

        easyp = easyprof.AppArmorEasyProfile(None, self.options)
        for i in easyp.get_templates():
            self.assertTrue(os.path.exists(i), "Could not find '%s'" % i)

    def test_policygroups_show(self):
        '''Test policygroups (show)'''
        files = []
        for f in glob.glob("%s/policygroups/*" % self.tmpdir):
            files.append(f)

        for f in files:
            args = self.full_args
            args += ['--show-template', '--template', f]
            (self.options, self.args) = easyprof.parse_args(args)
            easyp = easyprof.AppArmorEasyProfile(None, self.options)

            path = os.path.join(easyp.dirs['policygroups'], f)
            self.assertTrue(os.path.exists(path), "Could not find '%s'" % path)
            open(path).read()

#
# Test genpolicy
#
    def _gen_policy(self, name=None, template=None, extra_args=[]):
        '''Generate a policy'''
        # Build up our args
        args = self.full_args

        if template == None:
            args.append('--template=%s' % self.test_template)
        else:
            args.append('--template=%s' % template)

        if name != None:
            args.append('--name=%s' % name)

        if len(extra_args) > 0:
            args += extra_args

        args.append(self.binary)

        # Now parse our args
        (self.options, self.args) = easyprof.parse_args(args)
        easyp = easyprof.AppArmorEasyProfile(self.binary, self.options)
        params = easyprof.gen_policy_params(self.binary, self.options)
        p = easyp.gen_policy(**params)

        # We always need to check for these
        search_terms = [self.binary]
        if name != None:
            search_terms.append(name)

        if template == None:
            search_terms.append(self.test_template)

        for s in search_terms:
            self.assertTrue(s in p, "Could not find '%s' in:\n%s" % (s, p))

        # ###NAME### should be replaced with self.binary or 'name'. Check for that
        inv_s = '###NAME###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

        if debugging:
            sys.stdout.write("%s\n" % p)

        return p

    def test_genpolicy_templates_abspath(self):
        '''Test genpolicy (abspath to template)'''
        # create a new template
        template = os.path.join(self.tmpdir, "test-abspath-template")
        shutil.copy(os.path.join(self.tmpdir, 'templates', self.test_template), template)
        contents = open(template).read()
        test_string = "#teststring"
        open(template, 'w').write(contents + "\n%s\n" % test_string)

        p = self._gen_policy(template=template)

        for s in [self.test_template, test_string]:
            self.assertTrue(s in p, "Could not find '%s' in:\n%s" % (s, p))

    def test_genpolicy_templates_system(self):
        '''Test genpolicy (system template)'''
        self._gen_policy()

    def test_genpolicy_templates_nonexistent(self):
        '''Test genpolicy (nonexistent template)'''
        try:
            self._gen_policy(template=os.path.join(self.tmpdir, "/nonexistent"))
        except easyprof.AppArmorException:
            return
        except Exception:
            raise
        raise Exception ("template should be invalid")

    def test_genpolicy_name(self):
        '''Test genpolicy (name)'''
        self._gen_policy(name='test-foo')

    def test_genpolicy_comment(self):
        '''Test genpolicy (comment)'''
        s = "test comment"
        p = self._gen_policy(extra_args=['--comment=%s' % s])
        self.assertTrue(s in p, "Could not find '%s' in:\n%s" % (s, p))
        inv_s = '###COMMENT###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_author(self):
        '''Test genpolicy (author)'''
        s = "Archibald Poindexter"
        p = self._gen_policy(extra_args=['--author=%s' % s])
        self.assertTrue(s in p, "Could not find '%s' in:\n%s" % (s, p))
        inv_s = '###AUTHOR###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_copyright(self):
        '''Test genpolicy (copyright)'''
        s = "2112/01/01"
        p = self._gen_policy(extra_args=['--copyright=%s' % s])
        self.assertTrue(s in p, "Could not find '%s' in:\n%s" % (s, p))
        inv_s = '###COPYRIGHT###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_abstractions(self):
        '''Test genpolicy (single abstraction)'''
        s = "nameservice"
        p = self._gen_policy(extra_args=['--abstractions=%s' % s])
        search = "#include <abstractions/%s>" % s
        self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###ABSTRACTIONS###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_abstractions_multiple(self):
        '''Test genpolicy (multiple abstractions)'''
        abstractions = "authentication,X,user-tmp"
        p = self._gen_policy(extra_args=['--abstractions=%s' % abstractions])
        for s in abstractions.split(','):
            search = "#include <abstractions/%s>" % s
            self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###ABSTRACTIONS###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_policygroups(self):
        '''Test genpolicy (single policygroup)'''
        groups = self.test_policygroup
        p = self._gen_policy(extra_args=['--policy-groups=%s' % groups])

        for s in ['#include <abstractions/nameservice>', '#include <abstractions/gnome>']:
            self.assertTrue(s in p, "Could not find '%s' in:\n%s" % (s, p))
        inv_s = '###POLICYGROUPS###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_policygroups_multiple(self):
        '''Test genpolicy (multiple policygroups)'''
        test_policygroup2 = "test-policygroup2"
        contents = '''
  # %s
  #include <abstractions/kde>
  #include <abstractions/openssl>
''' % (self.test_policygroup)
        open(os.path.join(self.tmpdir, 'policygroups', test_policygroup2), 'w').write(contents)

        groups = "%s,%s" % (self.test_policygroup, test_policygroup2)
        p = self._gen_policy(extra_args=['--policy-groups=%s' % groups])

        for s in ['#include <abstractions/nameservice>',
                  '#include <abstractions/gnome>',
                  '#include <abstractions/kde>',
                  '#include <abstractions/openssl>']:
            self.assertTrue(s in p, "Could not find '%s' in:\n%s" % (s, p))
        inv_s = '###POLICYGROUPS###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_policygroups_nonexistent(self):
        '''Test genpolicy (nonexistent policygroup)'''
        try:
            self._gen_policy(extra_args=['--policy-groups=nonexistent'])
        except easyprof.AppArmorException:
            return
        except Exception:
            raise
        raise Exception ("policygroup should be invalid")

    def test_genpolicy_readpath_file(self):
        '''Test genpolicy (read-path file)'''
        s = "/opt/test-foo"
        p = self._gen_policy(extra_args=['--read-path=%s' % s])
        search = "%s r," % s
        self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###READPATH###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_readpath_home_file(self):
        '''Test genpolicy (read-path file in /home)'''
        s = "/home/*/test-foo"
        p = self._gen_policy(extra_args=['--read-path=%s' % s])
        search = "owner %s r," % s
        self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###READPATH###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_readpath_homevar_file(self):
        '''Test genpolicy (read-path file in @{HOME})'''
        s = "@{HOME}/test-foo"
        p = self._gen_policy(extra_args=['--read-path=%s' % s])
        search = "owner %s r," % s
        self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###READPATH###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_readpath_homedirs_file(self):
        '''Test genpolicy (read-path file in @{HOMEDIRS})'''
        s = "@{HOMEDIRS}/test-foo"
        p = self._gen_policy(extra_args=['--read-path=%s' % s])
        search = "owner %s r," % s
        self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###READPATH###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_readpath_dir(self):
        '''Test genpolicy (read-path directory/)'''
        s = "/opt/test-foo-dir/"
        p = self._gen_policy(extra_args=['--read-path=%s' % s])
        search_terms = ["%s r," % s, "%s** r," % s]
        for search in search_terms:
            self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###READPATH###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_readpath_dir_glob(self):
        '''Test genpolicy (read-path directory/*)'''
        s = "/opt/test-foo-dir/*"
        p = self._gen_policy(extra_args=['--read-path=%s' % s])
        search_terms = ["%s r," % os.path.dirname(s), "%s r," % s]
        for search in search_terms:
            self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###READPATH###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_readpath_dir_glob_all(self):
        '''Test genpolicy (read-path directory/**)'''
        s = "/opt/test-foo-dir/**"
        p = self._gen_policy(extra_args=['--read-path=%s' % s])
        search_terms = ["%s r," % os.path.dirname(s), "%s r," % s]
        for search in search_terms:
            self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###READPATH###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_readpath_multiple(self):
        '''Test genpolicy (read-path multiple)'''
        paths = ["/opt/test-foo",
                 "/home/*/test-foo",
                 "@{HOME}/test-foo",
                 "@{HOMEDIRS}/test-foo",
                 "/opt/test-foo-dir/",
                 "/opt/test-foo-dir/*",
                 "/opt/test-foo-dir/**"]
        args = []
        search_terms = []
        for s in paths:
            args.append('--read-path=%s' % s)
            # This mimics easyprof.gen_path_rule()
            owner = ""
            if s.startswith('/home/') or s.startswith("@{HOME"):
                owner = "owner "
            if s.endswith('/'):
                search_terms.append("%s r," % (s))
                search_terms.append("%s%s** r," % (owner, s))
            elif s.endswith('/**') or s.endswith('/*'):
                search_terms.append("%s r," % (os.path.dirname(s)))
                search_terms.append("%s%s r," % (owner, s))
            else:
                search_terms.append("%s%s r," % (owner, s))

        p = self._gen_policy(extra_args=args)
        for search in search_terms:
            self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###READPATH###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_readpath_bad(self):
        '''Test genpolicy (read-path bad)'''
        s = "bar"
        try:
            self._gen_policy(extra_args=['--read-path=%s' % s])
        except easyprof.AppArmorException:
            return
        except Exception:
            raise
        raise Exception ("read-path should be invalid")

    def test_genpolicy_writepath_file(self):
        '''Test genpolicy (write-path file)'''
        s = "/opt/test-foo"
        p = self._gen_policy(extra_args=['--write-path=%s' % s])
        search = "%s rwk," % s
        self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###READPATH###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_writepath_home_file(self):
        '''Test genpolicy (write-path file in /home)'''
        s = "/home/*/test-foo"
        p = self._gen_policy(extra_args=['--write-path=%s' % s])
        search = "owner %s rwk," % s
        self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###READPATH###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_writepath_homevar_file(self):
        '''Test genpolicy (write-path file in @{HOME})'''
        s = "@{HOME}/test-foo"
        p = self._gen_policy(extra_args=['--write-path=%s' % s])
        search = "owner %s rwk," % s
        self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###READPATH###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_writepath_homedirs_file(self):
        '''Test genpolicy (write-path file in @{HOMEDIRS})'''
        s = "@{HOMEDIRS}/test-foo"
        p = self._gen_policy(extra_args=['--write-path=%s' % s])
        search = "owner %s rwk," % s
        self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###READPATH###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_writepath_dir(self):
        '''Test genpolicy (write-path directory/)'''
        s = "/opt/test-foo-dir/"
        p = self._gen_policy(extra_args=['--write-path=%s' % s])
        search_terms = ["%s rwk," % s, "%s** rwk," % s]
        for search in search_terms:
            self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###READPATH###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_writepath_dir_glob(self):
        '''Test genpolicy (write-path directory/*)'''
        s = "/opt/test-foo-dir/*"
        p = self._gen_policy(extra_args=['--write-path=%s' % s])
        search_terms = ["%s rwk," % os.path.dirname(s), "%s rwk," % s]
        for search in search_terms:
            self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###READPATH###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_writepath_dir_glob_all(self):
        '''Test genpolicy (write-path directory/**)'''
        s = "/opt/test-foo-dir/**"
        p = self._gen_policy(extra_args=['--write-path=%s' % s])
        search_terms = ["%s rwk," % os.path.dirname(s), "%s rwk," % s]
        for search in search_terms:
            self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###READPATH###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_writepath_multiple(self):
        '''Test genpolicy (write-path multiple)'''
        paths = ["/opt/test-foo",
                 "/home/*/test-foo",
                 "@{HOME}/test-foo",
                 "@{HOMEDIRS}/test-foo",
                 "/opt/test-foo-dir/",
                 "/opt/test-foo-dir/*",
                 "/opt/test-foo-dir/**"]
        args = []
        search_terms = []
        for s in paths:
            args.append('--write-path=%s' % s)
            # This mimics easyprof.gen_path_rule()
            owner = ""
            if s.startswith('/home/') or s.startswith("@{HOME"):
                owner = "owner "
            if s.endswith('/'):
                search_terms.append("%s rwk," % (s))
                search_terms.append("%s%s** rwk," % (owner, s))
            elif s.endswith('/**') or s.endswith('/*'):
                search_terms.append("%s rwk," % (os.path.dirname(s)))
                search_terms.append("%s%s rwk," % (owner, s))
            else:
                search_terms.append("%s%s rwk," % (owner, s))

        p = self._gen_policy(extra_args=args)
        for search in search_terms:
            self.assertTrue(search in p, "Could not find '%s' in:\n%s" % (search, p))
        inv_s = '###READPATH###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_writepath_bad(self):
        '''Test genpolicy (write-path bad)'''
        s = "bar"
        try:
            self._gen_policy(extra_args=['--write-path=%s' % s])
        except easyprof.AppArmorException:
            return
        except Exception:
            raise
        raise Exception ("write-path should be invalid")

    def test_genpolicy_templatevar(self):
        '''Test genpolicy (template-var single)'''
        s = "@{FOO}=bar"
        p = self._gen_policy(extra_args=['--template-var=%s' % s])
        self.assertTrue(s in p, "Could not find '%s' in:\n%s" % (s, p))
        inv_s = '###TEMPLATEVAR###'
        self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_templatevar_multiple(self):
        '''Test genpolicy (template-var multiple)'''
        variables = ["@{FOO}=bar", "@{BAR}=baz"]
        args = []
        for s in variables:
            args.append('--template-var=%s' % s)

        p = self._gen_policy(extra_args=args)
        for s in variables:
            self.assertTrue(s in p, "Could not find '%s' in:\n%s" % (s, p))
            inv_s = '###TEMPLATEVAR###'
            self.assertFalse(inv_s in p, "Found '%s' in :\n%s" % (inv_s, p))

    def test_genpolicy_templatevar_bad(self):
        '''Test genpolicy (template-var bad)'''
        s = "{FOO}=bar"
        try:
            self._gen_policy(extra_args=['--template-var=%s' % s])
        except easyprof.AppArmorException:
            return
        except Exception:
            raise
        raise Exception ("template-var should be invalid")

    def test_genpolicy_invalid_template_policy(self):
        '''Test genpolicy (invalid template policy)'''
        # create a new template
        template = os.path.join(self.tmpdir, "test-invalid-template")
        shutil.copy(os.path.join(self.tmpdir, 'templates', self.test_template), template)
        contents = open(template).read()
        bad_pol = ""
        bad_string = "bzzzt"
        for line in contents.splitlines():
            if '}' in line:
                bad_pol += bad_string
            else:
                bad_pol += line
            bad_pol += "\n"
        open(template, 'w').write(bad_pol)
        try:
            self._gen_policy(template=template)
        except easyprof.AppArmorException:
            return
        except Exception:
            raise
        raise Exception ("policy should be invalid")


#
# End test class
#

#
# Main
#
if __name__ == '__main__':
    def cleanup(files):
        for f in files:
            if os.path.exists(f):
                os.unlink(f)

    absfn = os.path.abspath(sys.argv[0])
    topdir = os.path.dirname(os.path.dirname(absfn))

    if len(sys.argv) > 1 and (sys.argv[1] == '-d' or sys.argv[1] == '--debug'):
        debugging = True

    created = []

    # Create the necessary files to import aa-easyprof
    init = os.path.join(os.path.dirname(absfn), '__init__.py')
    if not os.path.exists(init):
        open(init, 'a').close()
        created.append(init)

    symlink = os.path.join(os.path.dirname(absfn), 'easyprof.py')
    if not os.path.exists(symlink):
        os.symlink(os.path.join(topdir, 'apparmor', 'easyprof.py'), symlink)
        created.append(symlink)
        created.append(symlink + 'c')

    # Now that we have everything we need, import aa-easyprof
    import easyprof

    # run the tests
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(T))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)

    cleanup(created)

    if not rc.wasSuccessful():
        sys.exit(1)
