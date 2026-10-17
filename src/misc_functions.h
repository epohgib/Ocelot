#ifndef SRC_MISC_FUNCTIONS_H_
#define SRC_MISC_FUNCTIONS_H_

// Copyright [2017-2026] Orpheus

#include <netinet/in.h>
#include <string>
#include <vector>

int32_t strtoint32(const std::string& str);
int64_t strtoint64(const std::string& str);
std::string hex_decode(const std::string &in);
std::string bintohex(const std::string &in);

// Splits on a single delimiter; empty pieces are kept.
std::vector<std::string> split(const std::string &s, char delim);

// True when the address is globally routable, i.e. not loopback, private,
// link-local, multicast, reserved or documentation (see the ranges below).
bool ipv4_is_public(in_addr addr);
bool ipv6_is_public(in6_addr addr);

#endif  // SRC_MISC_FUNCTIONS_H_
