#include "argparser.h"
#include "dns.h"
#include "udp.h"
#include "types.h"

#include <iostream>

int main(int argc, const char** argv) {
    DNSConfiguration args{};
    try {
        args = argparser::parseArguments(argc, argv);
    } catch (const std::system_error &err) {
        std::cerr << err.what();
        return -1;
    }

    dns::Packet queryPacket;
    dns::Server server;
    tie(queryPacket, server) = dns::constructQueryPacket(args);

    std::vector<uint8_t> response;
    try {
        response = udp::sendQuery(server.address, server.port, queryPacket);
    } catch (std::system_error &err) {
        std::cerr << err.what();
        return -1;
    }

    // Parse and display the response
    const auto result = dns::parseResponsePacket(response);
    std::cout << result << std::endl;

    return 0;
}
