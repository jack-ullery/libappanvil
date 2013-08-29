import unittest
import shutil

class Test(unittest.TestCase):

    def setUp(self):
        #copy the local profiles to the test directory
        shutil.copytree('/etc/apparmor.d/', './profiles/')

    def test_audit(self):
        pass
    
    def test_complain(self):
        pass
    
    def test_enforce(self):
        pass
    
    def test_disable(self):
        pass
    
    def test_autodep(self):
        pass


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()