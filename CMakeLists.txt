cmake_minimum_required(VERSION 3.26)
project(isa)

set(CMAKE_CXX_STANDARD 23)

add_executable(isa main.cpp
        argparser/argparser.h
        dns/dns.h
        udp/udp.h
        types.h
)
