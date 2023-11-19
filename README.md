# DNS resolver
> Skuratovich Aliaksandr, xskura01

## HOW TO RUN
1. `make` to compile or `make debug` to compile with debug enabled.
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
  * `requirements.txt` - requirements for testing .
  * `test_dns.py` - test script.

## REQUIREMENTS
    * python3. To check, simply run `python3 --version` in the terminal.
    * g++ compiler, c++20 standard.