#pragma once

#include <string>

typedef struct DNSConfiguration {
    bool recursionRequested;
    bool reverseQuery;
    bool queryTypeAAAA;
    std::string server;
    std::optional<uint16_t> port;
    std::string address;
} DNSConfiguration;
