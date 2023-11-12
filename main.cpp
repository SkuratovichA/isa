#include "argparser/argparser.h"
#include "dns/dns.h"
#include "udp/udp.h"
#include "types.h"

#include <iostream>

const auto DEFAULT_PORT = 53;

int main(int argc, const char** argv) {
    DNSConfiguration args{};
    try {
        args = argparser::parseArguments(argc, argv);
    } catch (const std::system_error &err) {
        std::cerr << err.what() << std::endl;
        return err.code().value();
    }

    std::cout << "Server: " << args.server << std::endl;
    if (args.port) {
        std::cout << "Port: " << *args.port << std::endl;
    }

    // Construct the DNS query packet
    auto queryPacket = DNS::constructQueryPacket(args);

    // Send the query and receive the response
    auto port = args.port.value_or(DEFAULT_PORT);
    std::string response = UDP::sendQuery(args.server, port, queryPacket);

    // Parse and display the response
    DNS::parseResponsePacket(response);

    return 0;
}
