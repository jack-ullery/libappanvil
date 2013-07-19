'''
Created on Jul 18, 2013

@author: kshitij
'''
import unittest
import sys

sys.path.append('../')
import apparmor.config as config

class Test(unittest.TestCase):


    def test_IniConfig(self):
        ini_config = config.Config('ini')
        ini_config.CONF_DIR = '.'
        conf = ini_config.read_config('logprof.conf')
        logprof_sections = ['settings', 'repository', 'qualifiers', 'required_hats', 'defaulthat', 'globs']
        logprof_sections_options = ['profiledir', 'inactive_profiledir', 'logfiles', 'parser', 'ldd', 'logger', 'default_owner_prompt', 'custom_includes']
        logprof_settings_parser = '/sbin/apparmor_parser /sbin/subdomain_parser'
        
        self.assertEqual(conf.sections(), logprof_sections)
        self.assertEqual(conf.options('settings'), logprof_sections_options)
        self.assertEqual(conf['settings']['parser'], logprof_settings_parser)
        
    def test_ShellConfig(self):
        shell_config = config.Config('shell')
        shell_config.CONF_DIR = '.'
        conf = shell_config.read_config('easyprof.conf')
        easyprof_sections = ['POLICYGROUPS_DIR', 'TEMPLATES_DIR']
        easyprof_Policygroup = '/usr/share/apparmor/easyprof/policygroups'
        easyprof_Templates = '/usr/share/apparmor/easyprof/templates'
        
        self.assertEqual(sorted(list(conf[''].keys())), sorted(easyprof_sections))
        self.assertEqual(conf['']['POLICYGROUPS_DIR'], easyprof_Policygroup)
        self.assertEqual(conf['']['TEMPLATES_DIR'], easyprof_Templates)
        
        


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testConfig']
    unittest.main()