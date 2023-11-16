#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstring>
#include <arpa/inet.h>
#include <sstream>
#include <tuple>

#include "argparser.h"
#include "types.h"


// DNS record types
const uint16_t typeA = 0x0001;
const uint16_t typeAAAA = 0x001C;
const uint16_t typePTR = 0x000C;
const uint16_t typeCNAME = 0x0005;

// flags
const uint16_t flagAuthoritative = 0x0400;
const uint16_t flagRecursive = 0x0100;
const uint16_t flagTrunc = 0x200;
const uint16_t flagRD = 0x0100;
const uint16_t packetCompressed = 0xC0;

// DNS record class
const uint16_t classInternet = 0x0001;

const uint16_t DEFAULT_DNS_PORT = 53;


std::vector<uint8_t> encodeDNSName(const std::string& domain) {
    std::vector<uint8_t> encodedName;
    size_t lastPos = 0;
    size_t pos = domain.find('.');
    while (pos != std::string::npos) {
        encodedName.push_back(static_cast<uint8_t>(pos - lastPos));
        for (size_t i = lastPos; i < pos; ++i) {
            encodedName.push_back(static_cast<uint8_t>(domain[i]));
        }
        lastPos = pos + 1;
        pos = domain.find('.', lastPos);
    }
    encodedName.push_back(static_cast<uint8_t>(domain.size() - lastPos));
    for (size_t i = lastPos; i < domain.size(); ++i) {
        encodedName.push_back(static_cast<uint8_t>(domain[i]));
    }
    encodedName.push_back(0);
    return encodedName;
}

std::string reverseIPv4(const std::string& ip) {
    struct sockaddr_in sa{};
    // validate
    if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 1) {
        throw std::system_error(EINVAL, std::system_category(), "Invalid IPv4 address");
    }

    char buffer[sizeof("069.420.420.069" "in-addr.arpa") + 1];
    snprintf(buffer, sizeof(buffer), "%d.%d.%d.%d.in-addr.arpa",
             (sa.sin_addr.s_addr >> 24) & 0xFF,
             (sa.sin_addr.s_addr >> 16) & 0xFF,
             (sa.sin_addr.s_addr >> 8) & 0xFF,
             (sa.sin_addr.s_addr >> 0) & 0xFF
    );
    return {buffer};
}

std::string reverseIPv6(const std::string& ip) {
    struct sockaddr_in6 sa{};
    // validate
    if (inet_pton(AF_INET6, ip.c_str(), &(sa.sin6_addr)) != 1) {
        throw std::system_error(EINVAL, std::system_category(), "Invalid IPv6 address");
    }

    const char* hexadec = "0123456789abcdef";
    std::string result;
    for (int i = sizeof(hexadec) - 1; i >= 0; --i) {
        uint8_t byte = sa.sin6_addr.s6_addr[i];
        result += hexadec[byte & 0x0F];
        result += '.';
        result += hexadec[byte >> 4];
        result += '.';
    }
    result += "ip6.arpa";
    return result;
}

struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

std::string parseDomainNameFromPacket(const std::vector<uint8_t>& packet, size_t& offset) {
    std::string name;
    bool jumped = false;
    size_t jump_offset = 0;

    while (packet[offset] != 0) {
        if (packet[offset] >= packetCompressed) {
            if (!jumped) {
                jump_offset = offset + 2;
                jumped = true;
            }
            uint16_t new_offset = ((packet[offset] & 0x3F) << 8) | packet[offset + 1];
            offset = new_offset;
        } else {
            if (!name.empty()) {
                name += '.';
            }
            size_t length = packet[offset++];
            for (size_t i = 0; i < length; ++i) {
                name += static_cast<char>(packet[offset++]);
            }
        }
    }
    offset = !jumped ? offset + 1 : jump_offset;

    return name;
}

std::string typeToString(uint16_t type) {
    switch (type) {
        case typeA:
            return "A";
        case typeAAAA:
            return "AAAA";
        case typeCNAME:
            return "CNAME";
        default:
            std::cerr << "unknown type: " << type << std::endl;
            return "UNKNOWN";
    }
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


        uint16_t qtype = args.queryTypeAAAA ? typeAAAA : typeA;
        if (args.reverseQuery) {
            qtype = typePTR;
            address = (args.queryTypeAAAA ? reverseIPv6 : reverseIPv4)(args.address);
        }
        std::vector<uint8_t> qname = encodeDNSName(address);
        packet.insert(packet.end(), qname.begin(), qname.end());

        packet.push_back(qtype >> 8); packet.push_back(qtype & 0xFF);
        packet.push_back(classInternet >> 8); packet.push_back(classInternet & 0xFF);

        return std::make_tuple(
            packet,
            (Server) {
                .port = args.port.value_or(DEFAULT_DNS_PORT),
                .address = args.server,
            }
        );
    }

    std::string parseResponsePacket(const std::vector<uint8_t>& response) {
        std::stringstream output;
        size_t offset = 0;

        // Parse the header
        DNSHeader header{};
        std::memcpy(&header, response.data() + offset, sizeof(DNSHeader));
        header.id = ntohs(header.id);
        header.flags = ntohs(header.flags);
        header.qdcount = ntohs(header.qdcount);
        header.ancount = ntohs(header.ancount);
        header.nscount = ntohs(header.nscount);
        header.arcount = ntohs(header.arcount);
        offset += sizeof(DNSHeader);

        // Print header flags
        output << "Authoritative: " << ((header.flags & flagAuthoritative) ? "Yes" : "No") << ", ";
        output << "Recursive: " << ((header.flags & flagRecursive) ? "Yes" : "No") << ", ";
        output << "Truncated: " << ((header.flags & flagTrunc) ? "Yes" : "No") << std::endl;

        // Print question section
        output << "Question section (" << header.qdcount << ")" << std::endl;
        for (int i = 0; i < header.qdcount; ++i) {
            std::string qname = parseDomainNameFromPacket(response, offset);
            uint16_t qtype = ntohs(*reinterpret_cast<const uint16_t*>(response.data() + offset));
            offset += 2;
            uint16_t qclass = ntohs(*reinterpret_cast<const uint16_t*>(response.data() + offset));
            offset += 2;
            output << qname << ", " << typeToString(qtype) << ", " << ((qclass == 1) ? "IN" : "UNKNOWN") << std::endl;
        }

        // Parse answer section
        output << "Answer section (" << header.ancount << ")" << std::endl;
        for (int i = 0; i < header.ancount; ++i) {
            std::string name = parseDomainNameFromPacket(response, offset);
            uint16_t type = ntohs(*reinterpret_cast<const uint16_t*>(response.data() + offset));
            offset += 2;
            uint16_t _class = ntohs(*reinterpret_cast<const uint16_t*>(response.data() + offset));
            offset += 2;
            uint32_t ttl = ntohl(*reinterpret_cast<const uint32_t*>(response.data() + offset));
            offset += 4;
            uint16_t rdlength = ntohs(*reinterpret_cast<const uint16_t*>(response.data() + offset));
            offset += 2;

            output << name << ", " << type << ", " << _class << ", " << ttl;

            if (type == typeA) {
                in_addr addr{};
                std::memcpy(&addr, response.data() + offset, sizeof(struct in_addr));
                output << ", " << inet_ntoa(addr);
            } else if (type == typeAAAA) {
                char ipv6_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, response.data() + offset, ipv6_str, INET6_ADDRSTRLEN);
                output << ", " << ipv6_str;
            } else if (type == typeCNAME) {
                std::string cname = parseDomainNameFromPacket(response, offset);
                output << ", " << cname;
            } else {
                std::cerr << "Unknown type: " << type << std::endl;
            }

            output << '\n';
            offset += rdlength;
        }

        output << "Authority section (" << header.nscount << ")" << std::endl;
        for (int i = 0; i < header.nscount; ++i) {
            std::string name = parseDomainNameFromPacket(response, offset);
            uint16_t type = ntohs(*reinterpret_cast<const uint16_t *>(response.data() + offset));
            offset += 2;
            uint16_t _class = ntohs(*reinterpret_cast<const uint16_t *>(response.data() + offset));
            offset += 2;
            uint32_t ttl = ntohl(*reinterpret_cast<const uint32_t *>(response.data() + offset));
            offset += 4;
            uint16_t rdlength = ntohs(*reinterpret_cast<const uint16_t *>(response.data() + offset));
            offset += 2;

            output << name << ", " << type << ", " << _class << ", " << ttl << ", [Data]\n";
            offset += rdlength;
        }

        output << "Additional section (" << header.arcount << ")" << std::endl;
        for (int i = 0; i < header.arcount; ++i) {
            std::string name = parseDomainNameFromPacket(response, offset);
            uint16_t type = ntohs(*reinterpret_cast<const uint16_t*>(response.data() + offset));
            offset += 2;
            uint16_t _class = ntohs(*reinterpret_cast<const uint16_t*>(response.data() + offset));
            offset += 2;
            uint32_t ttl = ntohl(*reinterpret_cast<const uint32_t*>(response.data() + offset));
            offset += 4;
            uint16_t rdlength = ntohs(*reinterpret_cast<const uint16_t*>(response.data() + offset));
            offset += 2;

            output << name << ", " << type << ", " << _class << ", " << ttl << ", [Data]\n";
            offset += rdlength;
        }

        return output.str();
    }
}
