
import unittest, subprocess as sub
from subprocess import Popen,PIPE
import os, sys

# Expected behavior for default flags
# Ideally, this should be True
default_expected = False

class GccSecurityTest00(unittest.TestCase):
    '''Test gcc security feature availability'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        os.chdir('gcc-security')
        self.mode = 'available'

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)
    
    def assertShellExitEquals(self, expected, cmd):
        return_code = sub.call(cmd,stdout=sub.PIPE,stderr=sub.PIPE)      
        self.assertEqual(return_code, expected)

    def shell_cmd(self, cmd):
        try:
            out = sub.check_output(cmd)
            return 0, out
        except sub.CalledProcessError as e:
            return e.returncode, e.message

    default_modes = ['strcpy', 'memcpy', 'sprintf', 'read', 'nada']



    # Generic glibc abort handler test
    def _test_overflow_handling(self, base_exec, abort_string, stack_protector=False, modes=default_modes):
        '''Generic tester for glibc aborts'''
   
        mapping = { base_exec + '-off': False,
                    base_exec + '-on': True,
                    base_exec + '-default': default_expected,
                  }
        map_list = [ base_exec + '-off', base_exec + '-on' ]
        if self.mode == 'by-default':
            map_list = [ base_exec + '-default' ]
        
        for target in map_list:
            for mode in modes:
                traces = ['sprintf']

                if mode != 'nada':
                    # check non-overflow case
                    cmd = ['./%s' % (target),mode,'A' * 40]
                    rc, output = self.shell_cmd(cmd)
                    self.assertEquals(rc, 0, 'rc(%d) != %d: %s\n' % (rc, 0, " ".join(cmd)) + output)

                for size in range(50,100,8):
                    cmd = ['./%s' % (target),mode,'A' * size]
                    rc, output = self.shell_cmd(cmd)
                    if rc in [-6,-11] or mode == 'nada':
                        break

                # short-circuit on the "invalid mode" test
                if mode == 'nada':
                    self.assertEquals(rc, 2)
                    continue

                # If the crash is caught by glibc, it is an abort,
                # otherwise it is an uncontrolled segmentation fault.
                rc_expected = -6
                if not mapping[target]:
                    rc_expected = -11
                self.assertEquals(rc, rc_expected, 'rc(%d) != %d: %s\n' % (rc, rc_expected, " ".join(cmd)) + output)

    def test_10_stack_protector(self):
        '''Stack protector'''

        self._test_overflow_handling('stack-protector', 'stack smashing detected', stack_protector=True)

    def test_11_stack_protector_strong(self):
        '''Stack protector strong'''
        self._test_overflow_handling('stack-protector-strong', 'stack smashing detected', stack_protector=True, modes=['memcpy', 'nada'])


    def test_20_relro(self):
        '''GNU_RELRO ELF section generated'''

        base_exec = 'relro'
        mapping = { base_exec + '-off': False,
                    base_exec + '-on': True,
                    base_exec + '-default': default_expected,
                  }
        map_list = [base_exec + '-off', base_exec + '-on']
        if self.mode == 'by-default':
            map_list = [base_exec + '-default']
        for target in map_list:
            p = Popen(['readelf', '-l', target], stdout=PIPE,stderr=PIPE)
            (output,err) = p.communicate()
            self.assertEquals(p.returncode, 0, str(output))
            self.assertTrue(mapping[target] == ('GNU_RELRO' in str(output)), str(output))

    def test_21_format_security(self):
        '''Format security checked at compile and runtime'''

        abort_expected = True
        base_exec = 'format-security'
        mapping = { base_exec + '-off': False,
                    base_exec + '-on': True,
                    base_exec + '-equal2': True,
                    base_exec + '-default': default_expected,
                  }
        map_list = [base_exec + '-off', base_exec + '-on', base_exec + '-equal2']
        if self.mode == 'by-default':
            map_list = [base_exec + '-default']
        for target in map_list:
            cmd = ['./%s' % (target), '%x%x%x%n%n%n%n']
            p = Popen(cmd, stdout=PIPE,stderr=PIPE)
            (out,err) = p.communicate()
            output = str(out + err)
            rc = p.returncode

            # If the crash is caught by stack-protector, it is an abort,
            # otherwise it is an uncontrolled segmentation fault.
            rc_expected = -11
            if mapping[target] and abort_expected:
                rc_expected = -6
            self.assertEquals(rc, rc_expected, 'rc(%d) != %d: %s\n' % (rc, rc_expected, " ".join(cmd)) + output)
  
    def test_23_buffer_overflow_protection(self):
        '''Buffer overflow protection'''

        self._test_overflow_handling('buffer-overflow', 'buffer overflow detected')


    def test_30_stack_protector_all(self):
        '''gcc -fstack-protector-all works when requested (LP: #691722)'''

        expected = 0
        target = 'stack-protector-all'
        cmd = ['../built-binaries/hardening-check', '-qpfrb', target]
        self.assertShellExitEquals(expected, cmd)

    def test_50_pie(self):
        '''ELF pie binaries'''

        base_exec = 'pie'
        mapping = { base_exec + '-off': False,
                    base_exec + '-on': True,
                    base_exec + '-default': default_expected,
                  }
        map_list = [base_exec + '-off', base_exec + '-on']
        if self.mode == 'by-default':
            map_list = [base_exec + '-default']
        for target in map_list:
            p = Popen(['readelf', '-h', target], stdout=PIPE,stderr=PIPE)
            (output,err) = p.communicate()
            self.assertEquals(p.returncode, 0, str(output))
            self.assertTrue(mapping[target] == ('DYN (Shared object file)' in str(output)), str(output))

    def test_60_bind_now(self):
        '''Linker set to BIND NOW binaries'''

        base_exec = 'bind-now'
        mapping = { base_exec + '-off': False,
                    base_exec + '-on': True,
                    base_exec + '-default': default_expected,
                    base_exec + '-pie-default': default_expected, #  test that bind_now is set when -pie is passed
                  }
        map_list = [base_exec + '-off', base_exec + '-on']
        if self.mode == 'by-default':
            map_list = [base_exec + '-default', base_exec + '-pie-default']
        for target in map_list:
            p = Popen(['readelf', '-d', target], stdout=PIPE,stderr=PIPE)
            (output,err) = p.communicate()
            self.assertEquals(p.returncode, 0, str(output))
            self.assertTrue(mapping[target] == ('(BIND_NOW)' in str(output)), target + ": " + str(output))

# Secondary class that enables all the "by default" tests
class GccSecurityTest01(GccSecurityTest00):
    '''Test gcc security features available'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        GccSecurityTest00.setUp(self)
        #self.announce('by default')
        self.mode = 'by-default'


# other things to test...
#~~~~~~~~~~~~~~~~~~~~~~~~
# ... ?

if __name__ == '__main__':
    unittest.main()
