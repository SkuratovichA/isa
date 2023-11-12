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


namespace udp {
    std::vector<uint8_t> sendQuery(const std::string& server, uint16_t port, const std::vector<uint8_t>& queryPacket) {
        // Determine if the server address is IPv4 or IPv6
        addrinfo hints{}, *res;
        hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
        hints.ai_socktype = SOCK_DGRAM; // Datagram socket
        hints.ai_flags = AI_NUMERICHOST; // Numeric address string

        int status = getaddrinfo(server.c_str(), nullptr, &hints, &res);
        if (status != 0) {
            throw std::runtime_error(gai_strerror(status));
        }

        // Create a UDP socket
        int sockfd = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP);
        if (sockfd < 0) {
            freeaddrinfo(res);
            throw std::system_error(errno, std::generic_category(), "Failed to create UDP socket");
        }

        // Set up the server address structure
        if (res->ai_family == AF_INET) { // IPv4
            auto *serv_addr = reinterpret_cast<sockaddr_in *>(res->ai_addr);
            serv_addr->sin_port = htons(port);
        } else if (res->ai_family == AF_INET6) { // IPv6
            auto *serv_addr = reinterpret_cast<sockaddr_in6 *>(res->ai_addr);
            serv_addr->sin6_port = htons(port);
        } else {
            close(sockfd);
            freeaddrinfo(res);
            throw std::runtime_error("Unsupported address family");
        }

        // Send the DNS query packet
        ssize_t sent_bytes = sendto(sockfd, queryPacket.data(), queryPacket.size(), 0, res->ai_addr, res->ai_addrlen);
        if (sent_bytes < 0) {
            close(sockfd);
            freeaddrinfo(res);
            throw std::system_error(errno, std::generic_category(), "Failed to send DNS query");
        }

        // Receive the DNS response packet
        std::vector<uint8_t> responseBuffer(512); // Standard DNS packet size
        ssize_t received_bytes = recvfrom(sockfd, responseBuffer.data(), responseBuffer.size(), 0, nullptr, nullptr);
        if (received_bytes < 0) {
            close(sockfd);
            freeaddrinfo(res);
            throw std::system_error(errno, std::generic_category(), "Failed to receive DNS response");
        }

        // Close the socket and free address info
        close(sockfd);
        freeaddrinfo(res);

        // Resize the buffer to the actual number of bytes received and return it
        responseBuffer.resize(received_bytes);
        return responseBuffer;
    }
}
