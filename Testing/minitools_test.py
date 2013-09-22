import atexit
import os
import shutil
import subprocess
import sys
import unittest
import filecmp

import apparmor.aa as apparmor

# Path for the program
test_path = '/usr/sbin/ntpd'
# Path for the target file containing profile
local_profilename = './profiles/usr.sbin.ntpd'

python_interpreter = 'python'
if sys.version_info >= (3,0):
    python_interpreter = 'python3'

class Test(unittest.TestCase):

    def test_audit(self):
        #Set ntpd profile to audit mode and check if it was correctly set
        str(subprocess.check_output('%s ./../Tools/aa-audit -d ./profiles %s'%(python_interpreter, test_path), shell=True))

        self.assertEqual(apparmor.get_profile_flags(local_profilename, test_path), 'audit', 'Audit flag could not be set in profile %s'%local_profilename)

        #Remove audit mode from ntpd profile and check if it was correctly removed
        subprocess.check_output('%s ./../Tools/aa-audit -d ./profiles -r %s'%(python_interpreter, test_path), shell=True)

        self.assertEqual(apparmor.get_profile_flags(local_profilename, test_path), None, 'Complain flag could not be removed in profile %s'%local_profilename)


    def test_complain(self):
        #Set ntpd profile to complain mode and check if it was correctly set
        subprocess.check_output('%s ./../Tools/aa-complain -d ./profiles %s'%(python_interpreter, test_path), shell=True)

        self.assertEqual(os.path.islink('./profiles/force-complain/%s'%os.path.basename(local_profilename)), True, 'Failed to create a symlink for %s in force-complain'%local_profilename)
        self.assertEqual(apparmor.get_profile_flags(local_profilename, test_path), 'complain', 'Complain flag could not be set in profile %s'%local_profilename)

        #Set ntpd profile to enforce mode and check if it was correctly set
        subprocess.check_output('%s ./../Tools/aa-complain -d ./profiles -r %s'%(python_interpreter, test_path), shell=True)

        self.assertEqual(os.path.islink('./profiles/force-complain/%s'%os.path.basename(local_profilename)), False, 'Failed to remove symlink for %s from force-complain'%local_profilename)
        self.assertEqual(os.path.islink('./profiles/disable/%s'%os.path.basename(local_profilename)), False, 'Failed to remove symlink for %s from disable'%local_profilename)
        self.assertEqual(apparmor.get_profile_flags(local_profilename, test_path), None, 'Complain flag could not be removed in profile %s'%local_profilename)

        # Set audit flag and then complain flag in a profile
        subprocess.check_output('%s ./../Tools/aa-audit -d ./profiles %s'%(python_interpreter, test_path), shell=True)
        subprocess.check_output('%s ./../Tools/aa-complain -d ./profiles %s'%(python_interpreter, test_path), shell=True)

        self.assertEqual(os.path.islink('./profiles/force-complain/%s'%os.path.basename(local_profilename)), True, 'Failed to create a symlink for %s in force-complain'%local_profilename)
        self.assertEqual(apparmor.get_profile_flags(local_profilename, test_path), 'audit,complain', 'Complain flag could not be set in profile %s'%local_profilename)

        #Remove complain flag first i.e. set to enforce mode
        subprocess.check_output('%s ./../Tools/aa-complain -d ./profiles -r %s'%(python_interpreter, test_path), shell=True)

        self.assertEqual(os.path.islink('./profiles/force-complain/%s'%os.path.basename(local_profilename)), False, 'Failed to remove symlink for %s from force-complain'%local_profilename)
        self.assertEqual(os.path.islink('./profiles/disable/%s'%os.path.basename(local_profilename)), False, 'Failed to remove symlink for %s from disable'%local_profilename)
        self.assertEqual(apparmor.get_profile_flags(local_profilename, test_path), 'audit', 'Complain flag could not be removed in profile %s'%local_profilename)

        #Remove audit flag
        subprocess.check_output('%s ./../Tools/aa-audit -d ./profiles -r %s'%(python_interpreter, test_path), shell=True)

    def test_enforce(self):
        #Set ntpd profile to complain mode and check if it was correctly set
        subprocess.check_output('%s ./../Tools/aa-enforce -d ./profiles -r %s'%(python_interpreter, test_path), shell=True)

        self.assertEqual(os.path.islink('./profiles/force-complain/%s'%os.path.basename(local_profilename)), True, 'Failed to create a symlink for %s in force-complain'%local_profilename)
        self.assertEqual(apparmor.get_profile_flags(local_profilename, test_path), 'complain', 'Complain flag could not be set in profile %s'%local_profilename)


        #Set ntpd profile to enforce mode and check if it was correctly set
        subprocess.check_output('%s ./../Tools/aa-enforce -d ./profiles %s'%(python_interpreter, test_path), shell=True)

        self.assertEqual(os.path.islink('./profiles/force-complain/%s'%os.path.basename(local_profilename)), False, 'Failed to remove symlink for %s from force-complain'%local_profilename)
        self.assertEqual(os.path.islink('./profiles/disable/%s'%os.path.basename(local_profilename)), False, 'Failed to remove symlink for %s from disable'%local_profilename)
        self.assertEqual(apparmor.get_profile_flags(local_profilename, test_path), None, 'Complain flag could not be removed in profile %s'%local_profilename)


    def test_disable(self):
        #Disable the ntpd profile and check if it was correctly disabled
        subprocess.check_output('%s ./../Tools/aa-disable -d ./profiles %s'%(python_interpreter, test_path), shell=True)

        self.assertEqual(os.path.islink('./profiles/disable/%s'%os.path.basename(local_profilename)), True, 'Failed to create a symlink for %s in disable'%local_profilename)

        #Enable the ntpd profile and check if it was correctly re-enabled
        subprocess.check_output('%s ./../Tools/aa-disable -d ./profiles -r %s'%(python_interpreter, test_path), shell=True)

        self.assertEqual(os.path.islink('./profiles/disable/%s'%os.path.basename(local_profilename)), False, 'Failed to remove a symlink for %s from disable'%local_profilename)


    def test_autodep(self):
        pass

    def test_cleanprof(self):
        input_file = 'cleanprof_test.in'
        output_file = 'cleanprof_test.out'
        #We position the local testfile
        shutil.copy('./%s'%input_file, './profiles')
        #Our silly test program whose profile we wish to clean
        cleanprof_test = '/usr/bin/a/simple/cleanprof/test/profile'

        subprocess.check_output('%s ./../Tools/aa-cleanprof  -d ./profiles -s %s' % (python_interpreter, cleanprof_test), shell=True)

        #Strip off the first line (#modified line)
        subprocess.check_output('sed -i 1d ./profiles/%s'%(input_file), shell=True)

        self.assertEqual(filecmp.cmp('./profiles/%s'%input_file, './%s'%output_file, False), True, 'Failed to cleanup profile properly')


def clean_profile_dir():
    #Wipe the local profiles from the test directory
    shutil.rmtree('./profiles')

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']

    if os.path.exists('./profiles'):
        shutil.rmtree('./profiles')

    #copy the local profiles to the test directory
    #Should be the set of cleanprofile
    shutil.copytree('/etc/apparmor.d', './profiles', symlinks=True)

    apparmor.profile_dir='./profiles'

    atexit.register(clean_profile_dir)

    unittest.main()
