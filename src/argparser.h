#pragma once

#include <string>
#include <optional>
#include <cstdint>
#include <getopt.h>
#include <system_error>
#include <iostream>

#include "utils.h"


void ThrowUsageMessage(const std::string &description) {
    auto retStr = (
        description.length() ? description + "\n\n" : ""
    ) + (
        "Usage: dns [-r] [-x] [-6] -s server [-p port] address\n"
        "-r: Recursion Desired\n"
        "-x: Reversed query\n"
        "-6: AAAA query\n"
        "-s: DNS server name or IP address\n"
        "-p port: port number to send a query, default is 53\n"
    );
    throw std::system_error(errno, std::generic_category(), retStr);
}

namespace argparser {

    DNSConfiguration parseArguments(int argc, const char **argv) {
        if (argc == 1) {
            ThrowUsageMessage("");
        }

        DNSConfiguration args{};
        int option;
        int currentIdx = 0;
        while ((option = getopt(argc, (char *const *) (argv), "rx6s:p:")) != -1) {
            currentIdx += 1;
            switch (option) {
                case 'r':
                    if (args.recursionRequested) {
                        ThrowUsageMessage("Recursion Desired (-r) flag can be specified only once");
                    }
                    args.recursionRequested = true;
                    break;
                case 'x':
                    if (args.reverseQuery) {
                        ThrowUsageMessage("Reversed query (-x) flag can be specified only once");
                    }
                    args.reverseQuery = true;
                    break;
                case '6':
                    if (args.queryTypeAAAA) {
                        ThrowUsageMessage("AAAA query (-6) flag can be specified only once");
                    }
                    args.queryTypeAAAA = true;
                    break;
                case 's':
                    if (!args.server.empty()) {
                        ThrowUsageMessage("Server (-s) parameter can be specified only once");
                    }
                    args.server = optarg;
                    break;
                case 'p':
                    if (args.port) {
                        ThrowUsageMessage("Port (-p) parameter can be specified only once");
                    }
                    args.port = static_cast<uint16_t>(std::stoi(optarg));
                    break;
                case '?':
                default:
                    ThrowUsageMessage("unknown option \"" + std::string(argv[currentIdx]) + "\"");
                    break;
            }
        }

        if (args.server.empty()) {
            ThrowUsageMessage("Server -s parameter must be specified");
        }

        if (optind == argc - 1) {
            args.address = argv[optind++];
        } else {
            ThrowUsageMessage("Too many arguments");
        }

        return args;
    }
}
