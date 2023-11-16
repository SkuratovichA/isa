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
const uint16_t TYPE_A = 0x0001;
const uint16_t TYPE_AAAA = 0x001C;
const uint16_t TYPE_PTR = 0x000C;
const uint16_t TYPE_CNAME = 0x0005;
const uint16_t TYPE_SOA = 0x0006;

// flags
const uint16_t FLAG_AUTHORITATIVE = 0x0400;
const uint16_t FLAG_RECURSIVE = 0x0100;
const uint16_t FLAG_TRUNC = 0x200;
const uint16_t FLAG_RD = 0x0100;
const uint16_t PACKET_COMPRESSED = 0xC0;

const uint16_t DEFAULT_DNS_PORT = 53;

// classes
const uint16_t CLASS_IN = 1;
const uint16_t CLASS_CS = 2;
const uint16_t CLASS_CH = 3;
const uint16_t CLASS_HS = 4;
const uint16_t CLASS_NONE = 254;
const uint16_t CLASS_ANY = 255;

struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};


namespace dns {
    struct Server {
        uint16_t port;
        std::string address;
    };

    typedef std::vector<uint8_t> Packet;

    namespace parsing {

        namespace utils {
            std::string classToString(const uint16_t qclass) {
                switch (qclass) {
                    case CLASS_IN:
                        return "IN";
                    case CLASS_CS:
                        return "CS";
                    case CLASS_CH:
                        return "CH";
                    case CLASS_HS:
                        return "HS";
                    case CLASS_NONE:
                        return "NONE";
                    case CLASS_ANY:
                        return "ANY";
                    default:
                        return "UNKNOWN";
                }
            }

            std::string typeToString(const uint16_t type) {
                switch (type) {
                    case TYPE_A:
                        return "A";
                    case TYPE_AAAA:
                        return "AAAA";
                    case TYPE_CNAME:
                        return "CNAME";
                    case TYPE_SOA:
                        return "SOA";
                    case TYPE_PTR:
                        return "PTR";
                    default:
                        std::cerr << "unknown type: " << type << std::endl;
                        return "UNKNOWN";
                }
            }

            std::string parseDomainNameFromPacket(const std::vector<uint8_t> &packet, size_t &offset) {
                std::string name;
                bool jumped = false;
                size_t jump_offset = 0;

                while (packet[offset] != 0) {
                    if (packet[offset] >= PACKET_COMPRESSED) {
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
        }

        typedef std::tuple<std::string, size_t> parserResult;

        parserResult parseSection(
                const std::vector<uint8_t> &response,
                size_t offset,
                const int count,
                const std::function<parserResult (const std::vector<uint8_t> &,
                                                                    size_t)> &parseFunction
        ) {
            std::stringstream output;
            for (int i = 0; i < count; ++i) {
                std::string sectionOutput;
                std::tie(sectionOutput, offset) = parseFunction(response, offset);
                output << sectionOutput;
            }
            return {output.str(), offset};
        }

        parserResult parseQuestionSection(const std::vector<uint8_t> &response, size_t offset) {
            std::stringstream output;
            std::string qname = utils::parseDomainNameFromPacket(response, offset);
            uint16_t qtype = ntohs(*reinterpret_cast<const uint16_t *>(response.data() + offset));
            offset += 2;
            uint16_t qclass = ntohs(*reinterpret_cast<const uint16_t *>(response.data() + offset));
            offset += 2;
            output << qname << ", " << utils::typeToString(qtype) << ", " << utils::classToString(qclass) << std::endl;
            return {output.str(), offset};
        }

        parserResult parseAnswerSection(const std::vector<uint8_t> &response, size_t offset) {
            std::stringstream output;
            std::string name = utils::parseDomainNameFromPacket(response, offset);
            uint16_t type = ntohs(*reinterpret_cast<const uint16_t *>(response.data() + offset));
            offset += 2;
            uint16_t ansclass = ntohs(*reinterpret_cast<const uint16_t *>(response.data() + offset));
            offset += 2;
            uint32_t ttl = ntohl(*reinterpret_cast<const uint32_t *>(response.data() + offset));
            offset += 4;
            offset += 2; // Skipping RDATA length

            output << name << ", " << utils::typeToString(type) << ", " << utils::classToString(ansclass) << ", " << ttl;

            auto processType = [&response, &offset, &type]() -> std::string {
                if (type == TYPE_A) {
                    in_addr addr{};
                    std::memcpy(&addr, response.data() + offset, sizeof(struct in_addr));
                    return ", " + std::string(inet_ntoa(addr));
                } else if (type == TYPE_AAAA) {
                    char ipv6_str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, response.data() + offset, ipv6_str, INET6_ADDRSTRLEN);
                    return ", " + std::string(ipv6_str);
                } else if (type == TYPE_CNAME) {
                    std::string cname = utils::parseDomainNameFromPacket(response, offset);
                    return ", " + std::string(cname);
                } else {
                    std::cerr << "Unknown type: " << type << std::endl;
                    return "";
                }
            };

            output << processType();
            output << '\n';
            return {output.str(), offset};
        }

        parserResult parseDefaultSection(const std::vector<uint8_t> &response, size_t offset) {
            std::stringstream output;
            std::string name = utils::parseDomainNameFromPacket(response, offset);
            const uint16_t type = ntohs(*reinterpret_cast<const uint16_t *>(response.data() + offset));
            offset += 2;
            const uint16_t authclass = ntohs(*reinterpret_cast<const uint16_t *>(response.data() + offset));
            offset += 2;
            const uint32_t ttl = ntohl(*reinterpret_cast<const uint32_t *>(response.data() + offset));
            offset += 4;
            const uint16_t rdlength = ntohs(*reinterpret_cast<const uint16_t *>(response.data() + offset));
            offset += 2;
            output << name << ", " << utils::typeToString(type) << ", " << utils::classToString(authclass) << ", " << ttl << ", [Data]\n";
            offset += rdlength;
            return {output.str(), offset};
        }

        parserResult parseAuthoritySection(const std::vector<uint8_t> &response, size_t offset) {
            return parseDefaultSection(response, offset);
        }

        parserResult parseAdditionalSection(const std::vector<uint8_t> &response, size_t offset) {
            return parseDefaultSection(response, offset);
        }
    }

    namespace constructorUtils {
        std::vector<uint8_t> encodeDNSName(const std::string &domain) {
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

        std::string reverseIPv4(const std::string &ip) {
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

        std::string reverseIPv6(const std::string &ip) {
            struct sockaddr_in6 sa{};
            // validate
            if (inet_pton(AF_INET6, ip.c_str(), &(sa.sin6_addr)) != 1) {
                throw std::system_error(EINVAL, std::system_category(), "Invalid IPv6 address");
            }

            const char *hexadec = "0123456789abcdef";
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
    }

    std::tuple<std::vector<uint8_t>, Server> constructQueryPacket(const DNSConfiguration &args) {
        std::vector<uint8_t> packet;
        std::string address = args.address;

        uint16_t flags = args.recursionRequested ? FLAG_RD : 0;

        packet.push_back(42);
        packet.push_back(69); // ID
        packet.push_back(flags >> 8);
        packet.push_back(flags & 0xFF);
        // QDCOUNT (number of questions)
        packet.push_back(0);
        packet.push_back(1);
        // ANCOUNT (number of answers)
        packet.push_back(0);
        packet.push_back(0);
        // NSCOUNT (number of authority records)
        packet.push_back(0);
        packet.push_back(0);
        // ARCOUNT (number of additional records)
        packet.push_back(0);
        packet.push_back(0);


        uint16_t qtype = args.queryTypeAAAA ? TYPE_AAAA : TYPE_A;
        if (args.reverseQuery) {
            qtype = TYPE_PTR;
            address = (args.queryTypeAAAA ? constructorUtils::reverseIPv6 : constructorUtils::reverseIPv4)(args.address);
        }
        std::vector<uint8_t> qname = constructorUtils::encodeDNSName(address);
        packet.insert(packet.end(), qname.begin(), qname.end());

        packet.push_back(qtype >> 8);
        packet.push_back(qtype & 0xFF);
        packet.push_back(CLASS_IN >> 8);
        packet.push_back(CLASS_IN & 0xFF);

        return std::make_tuple(
                packet,
                (Server) {
                        .port = args.port.value_or(DEFAULT_DNS_PORT),
                        .address = args.server,
                }
        );
    }

    std::string parseResponsePacket(const std::vector<uint8_t> &response) {
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
        output << "Authoritative: " << ((header.flags & FLAG_AUTHORITATIVE) ? "Yes" : "No") << ", ";
        output << "Recursive: " << ((header.flags & FLAG_RECURSIVE) ? "Yes" : "No") << ", ";
        output << "Truncated: " << ((header.flags & FLAG_TRUNC) ? "Yes" : "No") << std::endl;

        // Process sections
        std::string sectionOutput;
        output << "Question section (" << header.qdcount << ")" << std::endl;
        std::tie(sectionOutput, offset) = parsing::parseSection(response, offset, header.qdcount, parsing::parseQuestionSection);
        output << sectionOutput;

        output << "Answer section (" << header.ancount << ")" << std::endl;
        std::tie(sectionOutput, offset) = parsing::parseSection(response, offset, header.ancount, parsing::parseAnswerSection);
        output << sectionOutput;

        output << "Authority section (" << header.nscount << ")" << std::endl;
        std::tie(sectionOutput, offset) = parsing::parseSection(response, offset, header.nscount, parsing::parseAuthoritySection);
        output << sectionOutput;

        output << "Additional section (" << header.ancount << ")" << std::endl;
        std::tie(sectionOutput, offset) = parsing::parseSection(response, offset, header.arcount, parsing::parseAdditionalSection);
        output << sectionOutput;

        return output.str();
    }
}
