#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstring>
#include <arpa/inet.h>

#include "../argparser/argparser.h"
#include "../types.h"


const uint16_t flagRD = 0x0100; // Recursion Desired flag (1 bit)

// DNS record types
const uint16_t typeA = 0x0001; // Type A (IPv4 address)
const uint16_t typeAAAA = 0x001C; // Type AAAA (IPv6 address)
const uint16_t typePTR = 0x000C; // Type PTR (pointer)

// DNS record class
const uint16_t classInternet = 0x0001; // Class IN (Internet)

const uint16_t DEFAULT_DNS_PORT = 53;

// Function to encode a domain name into the DNS name format
std::vector<uint8_t> encodeDNSName(const std::string& domain) {
    std::vector<uint8_t> encodedName;
    size_t lastPos = 0;
    size_t pos = domain.find('.');
    while (pos != std::string::npos) {
        encodedName.push_back(static_cast<uint8_t>(pos - lastPos)); // label length
        for (size_t i = lastPos; i < pos; ++i) {
            encodedName.push_back(static_cast<uint8_t>(domain[i])); // label characters
        }
        lastPos = pos + 1;
        pos = domain.find('.', lastPos);
    }
    encodedName.push_back(static_cast<uint8_t>(domain.size() - lastPos)); // last label length
    for (size_t i = lastPos; i < domain.size(); ++i) {
        encodedName.push_back(static_cast<uint8_t>(domain[i])); // last label characters
    }
    encodedName.push_back(0); // null byte to end the QNAME
    return encodedName;
}

// validate ip4 address to handle potential errors
std::string reverseIPv4(const std::string& ip) {
    struct sockaddr_in sa{};
    char buffer[INET_ADDRSTRLEN];
    // Convert the IP address from string to binary form
    inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));
    // Convert the binary IP to a string in reverse order
    snprintf(buffer, INET_ADDRSTRLEN, "%d.%d.%d.%d.in-addr.arpa",
             (sa.sin_addr.s_addr >> 0) & 0xFF,
             (sa.sin_addr.s_addr >> 8) & 0xFF,
             (sa.sin_addr.s_addr >> 16) & 0xFF,
             (sa.sin_addr.s_addr >> 24) & 0xFF);
    return {buffer};
}

// validate ipv6 address to handle potential errors
std::string reverseIPv6(const std::string& ip) {
    struct sockaddr_in6 sa{};
    char buffer[INET6_ADDRSTRLEN];
    // Convert the IP address from string to binary form
    inet_pton(AF_INET6, ip.c_str(), &(sa.sin6_addr));
    // Convert the binary IP to a string in reverse order
    const char* hexadec = "0123456789abcdef";
    std::string result;
    for (int i = 15; i >= 0; --i) {
        // Process each byte of the address
        uint8_t byte = sa.sin6_addr.s6_addr[i];
        result += hexadec[byte & 0x0F];
        result += '.';
        result += hexadec[byte >> 4];
        result += '.';
    }
    result += "ip6.arpa";
    return result;
}

namespace dns {
    struct Server {
        uint16_t port;
        std::string address;
    };

    typedef std::vector<uint8_t> Packet;

    std::tuple<std::vector<uint8_t>, Server> constructQueryPacket(const DNSConfiguration& args) {
        std::vector<uint8_t> packet;
        std::string address = args.address;

        uint16_t flags = args.recursionRequested ? flagRD : 0;

        packet.push_back(42); packet.push_back(69); // ID
        packet.push_back(flags >> 8); packet.push_back(flags & 0xFF);
        // QDCOUNT (number of questions)
        packet.push_back(0); packet.push_back(1);
        // ANCOUNT (number of answers)
        packet.push_back(0); packet.push_back(0);
        // NSCOUNT (number of authority records)
        packet.push_back(0); packet.push_back(0);
        // ARCOUNT (number of additional records)
        packet.push_back(0); packet.push_back(0);

        // Question section
        std::vector<uint8_t> qname = encodeDNSName(args.address);
        packet.insert(packet.end(), qname.begin(), qname.end());

        uint16_t qtype = args.queryTypeAAAA ? typeAAAA : typeA;
        if (args.reverseQuery) {
            qtype = typePTR;
            address = args.queryTypeAAAA ? reverseIPv6(args.address) : reverseIPv4(args.address);
        }

        packet.push_back(qtype >> 8); packet.push_back(qtype & 0xFF);
        packet.push_back(classInternet >> 8); packet.push_back(classInternet & 0xFF);

        return std::make_tuple(
            packet,
            (Server) {
                .port = args.port.value_or(DEFAULT_DNS_PORT),
                .address = address,
            }
        );
    }

    // Function to parse a DNS response packet
    void parseResponsePacket(const std::vector<uint8_t>& response) {
        // Implementation of DNS response packet parsing (omitted for brevity)
    }
}
