# DNS resolver
> Skuratovich Aliaksandr, xskura01
> Date: 19.11.2023

The DNS resolver is a custom implementation of a DNS client that sends queries to DNS servers and displays received responses in a human-readable format. This program is specifically designed to handle the construction and analysis of DNS packets directly, without relying on external libraries for these core functionalities. Currently, it supports only UDP-based communication with DNS servers.

## Program Features
- **UDP Communication**: Uses UDP protocol for DNS query transmission and response reception in `src/udp.h`
- **Custom Packet Handling**: Implements its own DNS packet construction and parsing logic in `src/dns.h`
- **Query Types**: Supports standard queries, reverse DNS lookups, and AAAA record queries.
- **Recursion Option**: Allows the user to request recursive query resolution from the server.

## Limitations
- The program does not support TCP-based DNS communication.
- DNSSEC and other advanced DNS features are not implemented.

## HOW TO RUN
1. `make` to compile or `make debug` to compil(e with debug enabled.
2. `dns [-r] [-x] [-6] -s server [-p port] address`.
   Where
   * `-r`: Recursion Desired.
   * `-x`: Reversed query.
   * `-6`: AAAA query.
   * `-s`: DNS server name or IP address.
   * `-p port`: port number to send a query, default is 53.

## HOW TO TEST
To test, run `make test`. `test_log*` file will appear after testing.

## FILES
  * `src/*` - source files.
  * `manual.pdf` - documentation.
  * `Makefile` - makefile.
  * `requirements.txt` - requirements for testing.
  * `test_dns.py` - test script.

## REQUIREMENTS
  * python3. To check, simply run `python3 --version` in the terminal.
  * g++ compiler, c++20 standard.

