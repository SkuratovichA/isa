#include "argparser.h"
#include "dns.h"
#include "udp.h"
#include "utils.h"

#include <iostream>


const size_t TIMEOUT_SEC = 4;

int main(int argc, const char** argv) {
    DNSConfiguration args{};
    bool error = false;
    try {
        args = argparser::parseArguments(argc, argv);
    } catch (const std::system_error &err) {
        std::cerr << err.what() << std::endl;
        return -1;
    }

    // Construct the query packet
    dns::Packet queryPacket;
    dns::Server server;
    try {
        tie(queryPacket, server) = dns::constructQueryPacket(args);
    } catch (const std::system_error &err) {
        std::cerr << err.what() << std::endl;
        return -1;
    }

    // Send the query and receive the response
    std::vector<uint8_t> response;
    response = udp::sendQuery(server.address, server.port, args.address, queryPacket, TIMEOUT_SEC, error);
    if (error) {
        std::cerr << "Error while sending a query" << std::endl;
        return -1;
    }

    // Parse and display the response
    const auto result = dns::parseResponsePacket(response);
    std::cout << result;

    return 0;
}
