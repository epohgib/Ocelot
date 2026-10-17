#ifndef SRC_MISC_FUNCTIONS_H_
#define SRC_MISC_FUNCTIONS_H_

// Copyright [2017-2026] Orpheus

#include <netinet/in.h>
#include <string>

int32_t strtoint32(const std::string& str);
int64_t strtoint64(const std::string& str);
std::string hex_decode(const std::string &in);
std::string bintohex(const std::string &in);

// True when the address is globally routable, i.e. not loopback, private,
// link-local, multicast, reserved or documentation (see the ranges below).
bool ipv4_is_public(in_addr addr);
bool ipv6_is_public(in6_addr addr);

#endif  // SRC_MISC_FUNCTIONS_H_
