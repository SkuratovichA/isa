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


#ifdef DEBUG
#define debugMsg(msg) do {std::cout << msg; } while(0)
#else
#define debugMsg(msg) do {} while(0)
#endif
