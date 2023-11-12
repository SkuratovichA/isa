#pragma once

#include <vector>
#include <string>
#include <stdexcept>
#include <system_error>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <iostream>


const size_t DNS_PACKET_SIZE = 512;

namespace udp {
    std::vector<uint8_t> sendQuery(const std::string &server, uint16_t port, const std::vector<uint8_t> &queryPacket) {
        addrinfo hints{}, *res;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_NUMERICHOST;

        const auto status = getaddrinfo(server.c_str(), nullptr, &hints, &res);
        if (status != 0) {
            throw std::system_error(errno, std::generic_category(), gai_strerror(status));
        }

        const int sockfd = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP);
        if (sockfd < 0) {
            freeaddrinfo(res);
            throw std::system_error(errno, std::generic_category(), "Failed to create UDP socket");
        }

        switch (res->ai_family) {
            case AF_INET: {
                auto *serv_addr = reinterpret_cast<sockaddr_in *>(res->ai_addr);
                serv_addr->sin_port = htons(port);
                break;
            }
            case AF_INET6: {
                auto *serv_addr = reinterpret_cast<sockaddr_in6 *>(res->ai_addr);
                serv_addr->sin6_port = htons(port);
                break;
            }
            default:
                close(sockfd);
                freeaddrinfo(res);
                throw std::system_error(errno, std::generic_category(), "Unsupported address family");
        }


        ssize_t sent_bytes = sendto(sockfd, queryPacket.data(), queryPacket.size(), 0, res->ai_addr, res->ai_addrlen);
        if (sent_bytes < 0) {
            close(sockfd);
            freeaddrinfo(res);
            throw std::system_error(errno, std::generic_category(), "Failed to send DNS query");
        }

        std::vector<uint8_t> responseBuffer(DNS_PACKET_SIZE);
        ssize_t received_bytes = recvfrom(sockfd, responseBuffer.data(), responseBuffer.size(), 0, nullptr, nullptr);
        if (received_bytes < 0) {
            close(sockfd);
            freeaddrinfo(res);
            throw std::system_error(errno, std::generic_category(), "Failed to receive DNS response");
        }

        close(sockfd);
        freeaddrinfo(res);

        responseBuffer.resize(received_bytes);
        return responseBuffer;
    }
}
