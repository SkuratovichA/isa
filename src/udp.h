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
#include <memory>

#include "utils.h"


const size_t DNS_PACKET_SIZE = 512;

namespace udp {

    std::vector<uint8_t> sendQuery(const std::string &server, uint16_t port, const std::vector<uint8_t> &queryPacket, int timeoutSec) {
        addrinfo hints{}, *res;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;

        if (getIpAddrType(server) != ADDR_TYPE_UNKNOWN) {
            hints.ai_flags = AI_NUMERICHOST;
        }

        auto svaddr_status = getaddrinfo(server.c_str(), std::to_string(port).c_str(), &hints, &res);
        if (svaddr_status != 0) {
            throw std::system_error(svaddr_status, std::generic_category(), gai_strerror(svaddr_status));
        }
        std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> res_guard(res, freeaddrinfo);

        int sockfd = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP);
        if (sockfd < 0) {
            throw std::system_error(errno, std::generic_category(), "Failed to create UDP socket");
        }

        ssize_t sent_bytes = sendto(sockfd, queryPacket.data(), queryPacket.size(), 0, res->ai_addr, res->ai_addrlen);
        if (sent_bytes < 0) {
            close(sockfd);
            throw std::system_error(errno, std::generic_category(), "Failed to send DNS query");
        }

        timeval tv{};
        tv.tv_sec = timeoutSec;
        tv.tv_usec = 0;
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            close(sockfd);
            throw std::system_error(errno, std::generic_category(), "Failed to set socket timeout");
        }

        std::vector<uint8_t> responseBuffer(DNS_PACKET_SIZE);
        ssize_t received_bytes = recvfrom(sockfd, responseBuffer.data(), responseBuffer.size(), 0, nullptr, nullptr);
        if (received_bytes < 0) {
            close(sockfd);
            throw std::system_error(errno, std::generic_category(), "Failed to receive DNS response or timed out");
        }

        responseBuffer.resize(received_bytes);
        close(sockfd);
        return responseBuffer;
    }
}
