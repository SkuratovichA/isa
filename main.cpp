#include "argparser/argparser.h"
#include "dns/dns.h"
#include "udp/udp.h"
#include "types.h"

#include <iostream>

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
    dns::Packet queryPacket;
    dns::Server server;
    tie(queryPacket, server) = dns::constructQueryPacket(args);

    // Send the query and receive the response
    std::vector<uint8_t> response;
    try {
        response = udp::sendQuery(server.address, server.port, queryPacket);
    } catch (std::system_error &err) { // hui pizda. chto ya dolzhen lovitq?
        std::cerr << err.what() << std::endl;
        return err.code().value();
    }

    // Parse and display the response
    dns::parseResponsePacket(response);

    return 0;
}
