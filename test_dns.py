import unittest
import subprocess
import socket
from dns import resolver
from typing import List, Tuple


def get_servers(version: socket.AF_INET6 | socket.AF_INET) -> List:
    res = resolver.Resolver()
    servers = ['kazi.fit.vutbr.cz'] if socket.gethostname().endswith('fit.vutbr.cz') else []

    for server in res.nameservers:
        try:
            addr = socket.getaddrinfo(server, None)
            for family, _, _, _, sockaddr in addr:
                if family == version:
                    servers.append(sockaddr[0])
        except socket.gaierror:
            continue

    print(f'DNS SERVERS: {", ".join(set(servers))}')
    return list(set(servers))


def get_ipv6_servers() -> List:
    return get_servers(socket.AF_INET6)


def get_ipv4_servers() -> List:
    return get_servers(socket.AF_INET)


PROGRAM_NAME = './dns'

V4_SITES = [
    'https://ipv4.tlund.se',
]

V6_SITES = [
    'www.google.com',
    'www.fit.vut.cz',
]

V4_IPS = [
    '142.251.36.100',
    '86.49.229.96'
]

V6_IPS = [
    '2a03:2880:f11c:8183:face:b00c::25de',
    '2a00:1450:4001:81a::2004',
    '2606:4700:4700::1111',
    '2606:4700:4700::1001'
]


def get_non_rev_queres(sites: List, servers: List, v6: bool = False) -> List:
    return [
        (f'{PROGRAM_NAME} {param_opt} {rec_opt} -s {server} {address}', f'Test {rec_str} {param_opt} addr {address} server {server}', 0)
        for server in servers
        for address in sites
        for rec_str, rec_opt in [('iterative', ''), ('recursive', '-r')]
        for param_str, param_opt in ([('v6', '-6')] if v6 else [('', '')])
    ]


def get_reverse_queries(sites: List, servers: List, v6: bool = False) -> List:
    return [
        (
            f'{PROGRAM_NAME} {rec_opt} -x {param_opt} -s {server} {address}',
            f'Test {rec_str} {param_str} reversed addr {address} server {server}',
            0
        )
        for server in servers
        for address in sites
        for rec_str, rec_opt in [('iterative', ''), ('recursive', '-r')]
        for param_str, param_opt in ([('v6', '-6')] if v6 else [('', '')])
    ]


NON_REV_V4_QUERIES = get_non_rev_queres(V4_SITES, get_ipv4_servers())
REV_V4_QUERIES = get_reverse_queries(V4_IPS, get_ipv4_servers())

NON_REV_V6_QUERIES = get_non_rev_queres(V6_SITES, get_ipv6_servers(), True)
REV_V6_QUERIES = get_reverse_queries(V6_IPS, get_ipv6_servers(), True)

INVALID_ARGUMENTS = [
    (f'{PROGRAM_NAME}', 'No arguments', -1),
    (f'{PROGRAM_NAME} invalid', 'Invalid arguments', -1),
    (f'{PROGRAM_NAME} -s 1.1.1.1', 'Missing address', -1),
    (f'{PROGRAM_NAME} -s 1.1.1.1 -y www.fit.vut.cz', 'Invalid option', -1),
    (f'{PROGRAM_NAME} -s 1.1.1.1 www.fit.vut.cz -r', 'Invalid order', -1),
    (f'{PROGRAM_NAME} -s 1.1.1.1 -r www.fit.vut.cz www.fit.vut.cz', 'Excessive arguments', -1),
    (f'{PROGRAM_NAME} -s 1.1.1.1 -r www.fit.vut.cz -r', 'Duplicated arguments', -1),
    (f'{PROGRAM_NAME} -s 1.1.1.1 -r www.fit.vut.cz invalid', 'Invalid argument after all arguments', -1),
    (f'{PROGRAM_NAME} -s 1.1.1.1 -r www.fit.vut.cz -p "-9000"', 'Invalid port', -1),
]

INVALID_ADDRESSES = [
    (f'{PROGRAM_NAME} -s 999.999.999.999 www.fit.vut.cz', 'Invalid server', -1),
    (f'{PROGRAM_NAME} -s 8.8.8.8.8.8 www.fit.vut.cz', 'Invalid server', -1),
    (f'{PROGRAM_NAME} -s 8.8.8.8.8 "aaaaaa---aa---aaaaaa" ', 'Invalid address', -1),
]

TEST_CASES = (
        INVALID_ARGUMENTS +
        INVALID_ADDRESSES +

        NON_REV_V4_QUERIES +
        REV_V4_QUERIES +

        NON_REV_V6_QUERIES +
        REV_V6_QUERIES
)


class DNSInvalidArgumentTest(unittest.TestCase):
    def run_dns_command(self, command):
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        try:
            stdout, stderr = process.communicate(timeout=2)  # Set timeout to 2 seconds
            return stdout.decode('utf-8'), stderr.decode('utf-8'), process.returncode
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait()
            return "", "Command timed out", 69  # Indicate timeout with a specific return code
        finally:
            process.kill()
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()

    @staticmethod
    def make_test_method(command, assert_meth, desc):
        def test(self):
            o, e, c = self.run_dns_command(command)
            msg = f'{desc} - {assert_meth.__name__}({c}, 0)'
            getattr(self, assert_meth.__name__)(c, 0, msg)

        return test


def generate_test_cases():
    for i, (command, desc, expected_error_code) in enumerate(TEST_CASES):
        test_method_name = f'test_{i}_{desc.replace(" ", "_")}'
        test_method = DNSInvalidArgumentTest.make_test_method(
            command,
            DNSInvalidArgumentTest.assertEqual if expected_error_code == 0 else DNSInvalidArgumentTest.assertNotEqual,
            desc
        )
        test_method.__doc__ = command
        setattr(DNSInvalidArgumentTest, test_method_name, test_method)


generate_test_cases()

if __name__ == '__main__':
    unittest.main()
