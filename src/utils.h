#pragma once

#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct DNSConfiguration {
    bool recursionRequested;
    bool reverseQuery;
    bool queryTypeAAAA;
    std::string server;
    std::optional<uint16_t> port;
    std::string address;
} DNSConfiguration;


enum ADDR_TYPE {
    ADDR_TYPE_A,
    ADDR_TYPE_AAAA,
    ADDR_TYPE_UNKNOWN
};

ADDR_TYPE getIpAddrType(const std::string &address) {
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    if (inet_pton(AF_INET, address.c_str(), &(sa.sin_addr)) == 1) {
        return ADDR_TYPE_A;
    }
    // Fixed the placement of the parenthesis here
    if (inet_pton(AF_INET6, address.c_str(), &(sa6.sin6_addr)) == 1) {
        return ADDR_TYPE_AAAA;
    }
    return ADDR_TYPE_UNKNOWN;
}

#ifdef DEBUG
#define debugMsg(msg) do {std::cout << msg; } while(0)
#else
#define debugMsg(msg) do {} while(0)
#endif
