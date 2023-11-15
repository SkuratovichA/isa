import unittest
import subprocess

class DNSInvalidArgumentTest(unittest.TestCase):

    def run_dns_command(self, command):
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, stderr = process.communicate()
        return stdout.decode('utf-8'), stderr.decode('utf-8'), process.returncode

    def test_missing_server(self):
        command = "./dns -r www.fit.vut.cz"
        stdout, stderr, exit_code = self.run_dns_command(command)
        self.assertNotEqual(exit_code, 0)
        # self.assertIn("Error:", stderr)

    def test_invalid_server(self):
        command = "./dns -r -s invalid.server www.fit.vut.cz"
        stdout, stderr, exit_code = self.run_dns_command(command)
        self.assertNotEqual(exit_code, 0)
        # self.assertIn("Error:", stderr)

    def test_missing_address(self):
        command = "./dns -r -s kazi.fit.vutbr.cz"
        stdout, stderr, exit_code = self.run_dns_command(command)
        self.assertNotEqual(exit_code, 0)
        # self.assertIn("Error:", stderr)

    def test_invalid_option(self):
        command = "./dns -z -s kazi.fit.vutbr.cz www.fit.vut.cz"
        stdout, stderr, exit_code = self.run_dns_command(command)
        self.assertNotEqual(exit_code, 0)
        # self.assertIn("Error:", stderr)

    def test_valid_1(self):
        command = "./dns -6 -s 8.8.8.8 www.pornhub.com"
        stdout, stderr, exit_code = self.run_dns_command(command)
        self.assertEqual(exit_code, 0)


if __name__ == '__main__':
    unittest.main()
