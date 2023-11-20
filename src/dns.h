// Author: Aliaksandr Skuratovich (xskura01)

#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstring>
#include <arpa/inet.h>
#include <sstream>
#include <functional>
#include <tuple>

#include "argparser.h"
#include "utils.h"


// DNS record types
const uint16_t TYPE_A = 0x0001;
const uint16_t TYPE_AAAA = 0x001C;
const uint16_t TYPE_PTR = 0x000C;
const uint16_t TYPE_CNAME = 0x0005;
const uint16_t TYPE_NS = 0x0002;
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

const size_t INET6_ADDRLEN = 16;

struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

typedef std::tuple<std::string, size_t> parserResult;

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

            parserResult parseDomainNameFromPacket(const Packet &packet, size_t offset) {
                std::string name;
                bool jumped = false;
                size_t original_offset = offset;

                while (packet[offset] != 0) {
                    if (packet[offset] >= PACKET_COMPRESSED) {
                        if (!jumped) {
                            jumped = true;
                            original_offset = offset + 2;
                        }
                        offset = ((packet[offset] & 0x3F) << 8) | packet[offset + 1];
                    } else {
                        if (!name.empty()) {
                            name += '.';
                        }
                        size_t length = packet[offset++];
                        // Add error checking for length and packet size
                        for (size_t i = 0; i < length; ++i) {
                            name += static_cast<char>(packet[offset++]);
                        }
                    }
                }

                if (!jumped) {
                    offset++; // Skip the trailing 0
                } else {
                    offset = original_offset; // Use the original offset if compression was used
                }

                return {name, offset};
            }
        }

        parserResult parseSection(
                const Packet &response,
                size_t offset,
                const int count,
                const std::function<parserResult(const Packet &, size_t)> &parseFunction
        ) {
            std::stringstream output;
            debugMsg("Parsing section with " << count << " entries" << std::endl);
            for (int i = 0; i < count; ++i) {
                std::string sectionOutput;
                std::tie(sectionOutput, offset) = parseFunction(response, offset);
                debugMsg(
                    " >>> PARSED SECTION " << i
                    << ": offset " << offset << ", "
                    << "output \"" << sectionOutput << "\""
                    << std::endl
                );
                output << "  " << sectionOutput << '\n';
            }
            debugMsg("-----------------" << std::endl);
            return {output.str(), offset};
        }

        parserResult parseQuestionSection(const Packet &response, size_t offset) {
            std::stringstream output;
            std::string qname{};
            std::tie(qname, offset) = utils::parseDomainNameFromPacket(response, offset);
            uint16_t qtype = ntohs(*reinterpret_cast<const uint16_t *>(response.data() + offset));
            offset += 2;
            uint16_t qclass = ntohs(*reinterpret_cast<const uint16_t *>(response.data() + offset));
            offset += 2;

            output << qname << ", " << utils::typeToString(qtype) << ", " << utils::classToString(qclass);
            return {output.str(), offset};
        }

        parserResult parseAnswerSection(const Packet &response, size_t offset) {
            std::stringstream output;
            std::string name;
            std::tie(name, offset) = utils::parseDomainNameFromPacket(response, offset);

            // parse type
            uint16_t type = ntohs(*reinterpret_cast<const uint16_t *>(response.data() + offset));
            offset += 2;

            // ansclass
            uint16_t ansclass = ntohs(*reinterpret_cast<const uint16_t *>(response.data() + offset));
            offset += 2;

            // ttl
            uint32_t ttl = ntohl(*reinterpret_cast<const uint32_t *>(response.data() + offset));
            offset += 4;

            // rdlength
            offset += 2; // Skipping RDATA length

            output << name << ", " << utils::typeToString(type) << ", " << utils::classToString(ansclass) << ", " << ttl;

            switch (type) {
                case TYPE_A: {
                    in_addr addr{};
                    std::memcpy(&addr, response.data() + offset, sizeof(struct in_addr));
                    output << ", " + std::string(inet_ntoa(addr));
                    offset += sizeof(struct in_addr);
                    break;
                }
                case TYPE_AAAA: {
                    char ipv6_str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, response.data() + offset, ipv6_str, INET6_ADDRSTRLEN);
                    offset += INET6_ADDRLEN;
                    output << ", " + std::string(ipv6_str);
                    break;
                }
                case TYPE_CNAME: {
                    std::string cname;
                    std::tie(cname, offset) = utils::parseDomainNameFromPacket(response, offset);
                    output << ", " + cname;
                    break;
                }
                default:
                    return {"", offset};
            }

            return {output.str(), offset};
        }

        parserResult parseSOARecord(const Packet &response, size_t offset, size_t rdlength) {
            std::stringstream output;
            std::string mname, rname;
            size_t startOffset = offset;

            std::tie(mname, offset) = utils::parseDomainNameFromPacket(response, offset);
            std::tie(rname, offset) = utils::parseDomainNameFromPacket(response, offset);

            uint32_t serial = ntohl(*reinterpret_cast<const uint32_t *>(response.data() + offset));
            offset += 4;
            uint32_t refresh = ntohl(*reinterpret_cast<const uint32_t *>(response.data() + offset));
            offset += 4;
            uint32_t retry = ntohl(*reinterpret_cast<const uint32_t *>(response.data() + offset));
            offset += 4;
            uint32_t expire = ntohl(*reinterpret_cast<const uint32_t *>(response.data() + offset));
            offset += 4;
            uint32_t minimum = ntohl(*reinterpret_cast<const uint32_t *>(response.data() + offset));
            offset += 4;

            const auto rdlength_new = offset - startOffset;
            if (rdlength_new != rdlength) {
                std::cerr << "WARN: Invalid RDLENGTH for SOA record: " << "expect " << rdlength << ", got "
                          << rdlength_new << std::endl;
                return {output.str(), startOffset + rdlength};
            }

            output << mname << ", " << rname << ", " << serial << ", " << refresh << ", " << retry << ", " << expire
                   << ", " << minimum;
            return {output.str(), offset};
        }

        parserResult parseDefaultRecord(const Packet &response, size_t offset, size_t rdlength, const char *recordType) {
            std::stringstream output;
            std::string name;
            size_t startOffset = offset;

            std::tie(name, offset) = utils::parseDomainNameFromPacket(response, offset);

            const auto rdlength_new = offset - startOffset;
            if (rdlength_new != rdlength) {
                std::cerr << "WARN: Invalid RDLENGTH for" << recordType << " record: " << "expected " << rdlength
                          << ", got " << rdlength_new << std::endl;
                offset = startOffset + rdlength;
            }

            output << name;
            return {output.str(), offset};
        }

        parserResult parseTypeSpecificSection(uint16_t type, const Packet &response, size_t offset,
                                              uint16_t rdlength) {
            switch (type) {
                case TYPE_SOA:
                    return parseSOARecord(response, offset, rdlength);
                case TYPE_NS:
                    return parseDefaultRecord(response, offset, rdlength, "NS");
                case TYPE_CNAME:
                    return parseDefaultRecord(response, offset, rdlength, "CNAME");
                default:
                    return {"[Unsupported Type Data]", offset + rdlength};
            }
        }

        parserResult parseCommonSection(
                const Packet &response,
                size_t offset,
                const std::function<parserResult(const uint16_t type, const Packet &, size_t,uint16_t)> &parseTypeSpecific) {
            std::stringstream output;
            std::string name;
            std::tie(name, offset) = utils::parseDomainNameFromPacket(response, offset);

            const uint16_t type = ntohs(*reinterpret_cast<const uint16_t *>(response.data() + offset));
            offset += 2;
            const uint16_t authclass = ntohs(*reinterpret_cast<const uint16_t *>(response.data() + offset));
            offset += 2;
            const uint32_t ttl = ntohl(*reinterpret_cast<const uint32_t *>(response.data() + offset));
            offset += 4;
            const uint16_t rdlength = ntohs(*reinterpret_cast<const uint16_t *>(response.data() + offset));
            offset += 2;

            std::string typeSpecificOutput;
            std::tie(typeSpecificOutput, offset) = parseTypeSpecific(type, response, offset, rdlength);

            output << name << ", " << utils::typeToString(type) << ", " << utils::classToString(authclass) << ", "
                   << ttl << ", " << typeSpecificOutput;
            return {output.str(), offset};
        }

        parserResult parseAuthoritySection(const Packet &response, size_t offset) {
            return parseCommonSection(response, offset, parseTypeSpecificSection);
        }


        parserResult parseAdditionalSection(const Packet &response, size_t offset) {
            return parseCommonSection(
                    response,
                    offset,
                    [](const uint16_t type, const Packet &resp, size_t offs, uint16_t rdlen) {
                        return std::tuple(std::string("[Additional Data]"), offs + rdlen);
                    }
            );
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

            if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 1) {
                throw std::system_error(EINVAL, std::system_category(), "Invalid IPv4 address");
            }

            std::stringstream buffer;
            for (int i = 0; i < 4; i++) {
                buffer << std::to_string((sa.sin_addr.s_addr >> (i * 8)) & 0xFF) << ".";
            }
            buffer << "in-addr.arpa";
            return buffer.str();
        }

        std::string reverseIPv6(const std::string &ip) {
            struct sockaddr_in6 sa{};
            // validate
            if (inet_pton(AF_INET6, ip.c_str(), &(sa.sin6_addr)) != 1) {
                throw std::system_error(EINVAL, std::system_category(), "Invalid IPv6 address");
            }

            const char *hexadec = "0123456789abcdef";
            std::string result;
            for (int i = 15; i >= 0; --i) {
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

    std::tuple<Packet, Server> constructQueryPacket(const DNSConfiguration &args) {
        Packet packet;
        std::string address = args.address;

        uint16_t flags = args.recursionRequested ? FLAG_RD : 0;

        packet.push_back(42); packet.push_back(69); // ID
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
            address = (args.queryTypeAAAA ? constructorUtils::reverseIPv6 : constructorUtils::reverseIPv4)(
                    args.address);
        }
        std::vector<uint8_t> qname = constructorUtils::encodeDNSName(address);
        packet.insert(packet.end(), qname.begin(), qname.end());

        packet.push_back(qtype >> 8);
        packet.push_back(qtype & 0xFF);
        packet.push_back(CLASS_IN >> 8);
        packet.push_back(CLASS_IN & 0xFF);

        return {
            packet,
            (Server) {
                .port = args.port.value_or(DEFAULT_DNS_PORT),
                .address = args.server,
             }
        };
    }

    std::string parseResponsePacket(const Packet &response) {
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
        debugMsg("PARSE QUESTION SECTION" << std::endl);
        std::string sectionOutput;
        output << "Question section (" << header.qdcount << ")" << std::endl;
        std::tie(sectionOutput, offset) = parsing::parseSection(
                response, offset, header.qdcount,
                parsing::parseQuestionSection
        );
        output << sectionOutput;

        // fixme: the error is maybe here in answer so I increase too much of offset at the end of the function
        debugMsg("PARSE ANSWER SECTION" << std::endl);
        output << "Answer section (" << header.ancount << ")" << std::endl;
        std::tie(sectionOutput, offset) = parsing::parseSection(
                response, offset, header.ancount,
                parsing::parseAnswerSection
        );
        output << sectionOutput;

        debugMsg("PARSE AUTHORITY SECTION" << std::endl);
        output << "Authority section (" << header.nscount << ")" << std::endl;
        std::tie(sectionOutput, offset) = parsing::parseSection(
                response, offset, header.nscount,
                parsing::parseAuthoritySection
        );
        output << sectionOutput;

        debugMsg("PARSE ADDITIONAL SECTION" << std::endl);
        output << "Additional section (" << header.arcount << ")" << std::endl;
        std::tie(sectionOutput, offset) = parsing::parseSection(
                response, offset, header.arcount,
                parsing::parseAdditionalSection
        );
        output << sectionOutput;

        debugMsg("\n\n");
        return output.str();
    }
}
