// Copyright [2017-2026] Orpheus

#include <arpa/inet.h>

#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

#include "misc_functions.h"

int32_t strtoint32(const std::string& str) {
    std::istringstream stream(str);
    int32_t i = 0;
    stream >> i;
    return i;
}

int64_t strtoint64(const std::string& str) {
    std::istringstream stream(str);
    int64_t i = 0;
    stream >> i;
    return i;
}

std::string hex_decode(const std::string &in) {
    std::string out;
    out.reserve(20);
    unsigned int in_length = in.length();
    for (unsigned int i = 0; i < in_length; i++) {
        unsigned char x = '0';
        if (in[i] == '%' && (i + 2) < in_length) {
            i++;
            if (in[i] >= 'a' && in[i] <= 'f') {
                x = static_cast<unsigned char>((in[i]-87) << 4);
            } else if (in[i] >= 'A' && in[i] <= 'F') {
                x = static_cast<unsigned char>((in[i]-55) << 4);
            } else if (in[i] >= '0' && in[i] <= '9') {
                x = static_cast<unsigned char>((in[i]-48) << 4);
            }

            i++;
            if (in[i] >= 'a' && in[i] <= 'f') {
                x += static_cast<unsigned char>(in[i]-87);
            } else if (in[i] >= 'A' && in[i] <= 'F') {
                x += static_cast<unsigned char>(in[i]-55);
            } else if (in[i] >= '0' && in[i] <= '9') {
                x += static_cast<unsigned char>(in[i]-48);
            }
        } else {
            x = in[i];
        }
        out.push_back(x);
    }
    return out;
}

std::string bintohex(const std::string &in) {
    std::string out;
    size_t length = in.length();
    out.reserve(2*length);
    for (unsigned int i = 0; i < length; i++) {
        unsigned char x = static_cast<unsigned char>((in[i] & 0xF0) >> 4);
        if (x > 9) {
            x += 'a' - 10;
        } else {
            x += '0';
        }
        out.push_back(x);
        x = in[i] & 0x0F;
        if (x > 9) {
            x += 'a' - 10;
        } else {
            x += '0';
        }
        out.push_back(x);
    }
    return out;
}

namespace {

// Compares the leading `length` bytes of an address against a prefix.
bool prefix_match(const uint8_t *addr, const uint8_t *prefix, size_t length) {
    return std::memcmp(addr, prefix, length) == 0;
}

}  // namespace

// Rejected ranges (Radiance's set, extended with this-network, documentation,
// multicast and reserved): 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
// 169.254.0.0/16, 172.16.0.0/12, 192.0.2.0/24, 192.168.0.0/16,
// 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4.
bool ipv4_is_public(in_addr addr) {
    uint32_t ip = ntohl(addr.s_addr);

    if ((ip & 0xff000000) == 0x00000000) return false;  // 0.0.0.0/8 this-network
    if ((ip & 0xff000000) == 0x0a000000) return false;  // 10.0.0.0/8 private
    if ((ip & 0xffc00000) == 0x64400000) return false;  // 100.64.0.0/10 CGNAT
    if ((ip & 0xff000000) == 0x7f000000) return false;  // 127.0.0.0/8 loopback
    if ((ip & 0xffff0000) == 0xa9fe0000) return false;  // 169.254.0.0/16 link-local
    if ((ip & 0xfff00000) == 0xac100000) return false;  // 172.16.0.0/12 private
    if ((ip & 0xffffff00) == 0xc0000200) return false;  // 192.0.2.0/24 documentation
    if ((ip & 0xffff0000) == 0xc0a80000) return false;  // 192.168.0.0/16 private
    if ((ip & 0xffffff00) == 0xc6336400) return false;  // 198.51.100.0/24 documentation
    if ((ip & 0xffffff00) == 0xcb007100) return false;  // 203.0.113.0/24 documentation
    if ((ip & 0xf0000000) == 0xe0000000) return false;  // 224.0.0.0/4 multicast
    if ((ip & 0xf0000000) == 0xf0000000) return false;  // 240.0.0.0/4 reserved

    return true;
}

// Rejected ranges: ::/128, ::1/128, ::ffff:0:0/96, 100::/64, 2001::/32,
// 2001:db8::/32, 2002::/16, 3ffe::/16, fc00::/7, fe80::/10, fec0::/10.
// Matched on the leading bytes of s6_addr (portable; s6_addr32/s6_addr16 are
// glibc extensions).
bool ipv6_is_public(in6_addr addr) {
    const uint8_t *b = addr.s6_addr;
    static const uint8_t zero[16] = {};
    static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    static const uint8_t discard[8] = {0x01};
    static const uint8_t teredo[4] = {0x20, 0x01, 0x00, 0x00};
    static const uint8_t documentation[4] = {0x20, 0x01, 0x0d, 0xb8};
    static const uint8_t sixtofour[2] = {0x20, 0x02};
    static const uint8_t sixbone[2] = {0x3f, 0xfe};

    if (prefix_match(b, zero, 16)) return false;                                  // ::/128 unspecified
    if (prefix_match(b, zero, 15) && b[15] == 0x01) return false;                 // ::1/128 loopback
    if (prefix_match(b, mapped, 12)) return false;                                // ::ffff:0:0/96 IPv4-mapped
    if (prefix_match(b, discard, 8)) return false;                                // 100::/64 discard-only
    if (prefix_match(b, teredo, 4)) return false;                                 // 2001::/32 Teredo
    if (prefix_match(b, documentation, 4)) return false;                          // 2001:db8::/32 documentation
    if (prefix_match(b, sixtofour, 2)) return false;                              // 2002::/16 6to4
    if (prefix_match(b, sixbone, 2)) return false;                                // 3ffe::/16 6bone
    if ((b[0] & 0xfe) == 0xfc) return false;                                      // fc00::/7 unique local
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return false;                      // fe80::/10 link-local
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0xc0) return false;                      // fec0::/10 site-local

    return true;
}
