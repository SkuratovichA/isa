// Author: Aliaksandr Skuratovich (xskura01)

#include "argparser.h"
#include "dns.h"
#include "udp.h"
#include "utils.h"

#include <iostream>


const size_t TIMEOUT_SEC = 4;

int main(int argc, const char** argv) {
    DNSConfiguration args{};
    try {
        args = argparser::parseArguments(argc, argv);
    } catch (const std::system_error &err) {
        std::cerr << err.what() << std::endl;
        return -1;
    }

    dns::Packet queryPacket;
    dns::Server server;
    try {
        tie(queryPacket, server) = dns::constructQueryPacket(args);
    } catch (const std::system_error &err) {
        std::cerr << err.what() << std::endl;
        return -1;
    }

    std::vector<uint8_t> response;
    try {
        debugMsg("Sending DNS query to " << server << ":" << port << " for " << address << std::endl);
        response = udp::sendQuery(server.address, server.port, queryPacket, TIMEOUT_SEC);
    } catch (std::system_error &err) {
        std::cerr << err.what() << std::endl;
        return -1;
    }

    const auto result = dns::parseResponsePacket(response);
    std::cout << result;

    return 0;
}
