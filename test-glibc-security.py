import unittest
import os, sys
import subprocess as sub

class GlibcSecurityTest(unittest.TestCase):
    '''Test glibc security features'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        os.chdir('glibc-security')

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)

    def assertShellExitEquals(self, expected, cmd):
        return_code = sub.call(cmd,stdout=sub.PIPE,stderr=sub.PIPE)      
        self.assertEqual(return_code, expected)

    def test_11_heap_protector(self):
        '''glibc heap protection'''

        self.assertShellExitEquals(0, ["./heap","safe"])
        self.assertShellExitEquals(-6, ["./heap","unsafe"])

    def test_11_sprintf_unmangled(self):
        '''sprintf not pre-truncated with -D_FORTIFY_SOURCE=2'''
        expected = 0
        self.assertShellExitEquals(expected, ["./sprintf"])

    def test_12_glibc_pointer_obfuscation(self):
        '''glibc pointer obfuscation'''

        # values specific to MVP (amd64 arch)
        jb_pc = '7'
        jb_unenc = '-1'
        expected = 0

        self.assertShellExitEquals(2, ["./ptr-enc",'-1','-1'])
        self.assertShellExitEquals(200, ["./ptr-enc",'-2','-2'])
        self.assertShellExitEquals(expected, ["./ptr-enc",jb_pc,jb_unenc])

    def test_13_select_overflow(self):
        '''select macros detect overflow with -D_FORTIFY_SOURCE=2'''
        expected = -6
        self.assertShellExitEquals(0, ["./select", "200"])
        self.assertShellExitEquals(expected, ["./select", "1500"])
        self.assertShellExitEquals(expected, ["./select", "-100"])

 
    def test_80_stack_guard_exists(self):
        '''Stack guard exists'''
        expected = 0
        self.assertShellExitEquals(0, ["./guard"])
    
    def test_81_stack_guard_leads_zero(self):
        '''Stack guard leads with zero byte'''

        expected = 0
        self.assertShellExitEquals(0, ["./guard"])
        if expected == 0:
            # Try three times just to avoid randomized luck
            p = sub.Popen(["./guard"],stdout=sub.PIPE,stderr=sub.PIPE)
            rc, one = p.communicate()
            self.assertEqual(rc.startswith('00 '), True, one)
            p = sub.Popen(["./guard"],stdout=sub.PIPE,stderr=sub.PIPE)
            rc, two = p.communicate()
            self.assertEqual(rc.startswith('00 '), True, two)
            p = sub.Popen(["./guard"],stdout=sub.PIPE,stderr=sub.PIPE)
            rc, three = p.communicate()
            self.assertEqual(rc.startswith('00 '), True, three)

 
if __name__ == '__main__':
    unittest.main()
