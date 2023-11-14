#pragma once

#include <string>
#include <optional>
#include <cstdint>
#include <getopt.h>
#include <system_error>
#include <iostream>

#include "types.h"


void ThrowUsageMessage(const std::string &description) {
    auto retStr = (
        description.length() ? description + "\n\n" : ""
    ) + (
        "Usage: dns [-r] [-x] [-6] -s server [-p port] address\n"
        "-r: Recursion Desired\n"
        "-x: Reversed query\n"
        "-6: AAAA query.\n"
        "-s: DNS server name or IP adderess.\n"
        "-p port: port number to send a query. 53 by default.\n"
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
                    args.recursionRequested = true;
                    break;
                case 'x':
                    args.reverseQuery = true;
                    break;
                case '6':
                    args.queryTypeAAAA = true;
                    break;
                case 's':
                    args.server = optarg;
                    break;
                case 'p':
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
