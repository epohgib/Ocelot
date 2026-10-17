// Unit tests for ipv4_is_public() / ipv6_is_public().
// Built as the `test_ip` target and run with `ctest` (see CMakeLists.txt).

#include <arpa/inet.h>

#include <cstdio>
#include <cstdlib>

#include "misc_functions.h"

namespace {

int failures = 0;

in_addr parse_v4(const char *text) {
    in_addr addr{};
    if (inet_pton(AF_INET, text, &addr) != 1) {
        std::fprintf(stderr, "FATAL: cannot parse IPv4 test address '%s'\n", text);
        std::exit(2);
    }
    return addr;
}

in6_addr parse_v6(const char *text) {
    in6_addr addr{};
    if (inet_pton(AF_INET6, text, &addr) != 1) {
        std::fprintf(stderr, "FATAL: cannot parse IPv6 test address '%s'\n", text);
        std::exit(2);
    }
    return addr;
}

void expect_v4(const char *text, bool expected_public) {
    bool actual = ipv4_is_public(parse_v4(text));
    if (actual != expected_public) {
        std::fprintf(stderr, "FAIL: %s is %s, expected %s\n", text,
                     actual ? "public" : "private",
                     expected_public ? "public" : "private");
        failures++;
    }
}

void expect_v6(const char *text, bool expected_public) {
    bool actual = ipv6_is_public(parse_v6(text));
    if (actual != expected_public) {
        std::fprintf(stderr, "FAIL: %s is %s, expected %s\n", text,
                     actual ? "public" : "private",
                     expected_public ? "public" : "private");
        failures++;
    }
}

}  // namespace

int main() {
    // IPv4 rejected, one case per range of the plan plus range boundaries.
    expect_v4("0.0.0.1", false);            // 0.0.0.0/8 this-network
    expect_v4("10.1.2.3", false);           // 10.0.0.0/8 private
    expect_v4("100.64.0.1", false);         // 100.64.0.0/10 CGNAT, lower edge
    expect_v4("100.127.255.255", false);    // 100.64.0.0/10 CGNAT, upper edge
    expect_v4("127.0.0.1", false);          // 127.0.0.0/8 loopback
    expect_v4("169.254.1.1", false);        // 169.254.0.0/16 link-local
    expect_v4("172.16.0.1", false);         // 172.16.0.0/12 private, lower edge
    expect_v4("172.31.255.255", false);     // 172.16.0.0/12 private, upper edge
    expect_v4("192.0.2.1", false);          // 192.0.2.0/24 documentation
    expect_v4("192.168.1.1", false);        // 192.168.0.0/16 private
    expect_v4("198.51.100.10", false);      // 198.51.100.0/24 documentation
    expect_v4("203.0.113.50", false);       // 203.0.113.0/24 documentation
    expect_v4("224.0.0.5", false);          // 224.0.0.0/4 multicast, lower edge
    expect_v4("239.255.255.255", false);    // 224.0.0.0/4 multicast, upper edge
    expect_v4("240.0.0.1", false);          // 240.0.0.0/4 reserved
    expect_v4("255.255.255.255", false);    // limited broadcast

    // IPv4 accepted.
    expect_v4("8.8.8.8", true);
    expect_v4("1.1.1.1", true);
    expect_v4("100.128.0.1", true);         // just outside CGNAT
    expect_v4("172.32.0.1", true);          // just outside 172.16.0.0/12
    expect_v4("223.255.255.255", true);     // just below multicast

    // IPv6 rejected, one case per range of the plan plus range boundaries.
    expect_v6("::", false);                                 // ::/128 unspecified
    expect_v6("::1", false);                                // ::1/128 loopback
    expect_v6("::ffff:8.8.8.8", false);                     // ::ffff:0:0/96 IPv4-mapped
    expect_v6("100::1", false);                             // 100::/64 discard-only
    expect_v6("100::ffff:ffff:ffff:ffff", false);           // 100::/64, upper edge
    expect_v6("2001::1", false);                            // 2001::/32 Teredo
    expect_v6("2001:0:ffff:ffff:ffff:ffff:ffff:ffff", false);  // 2001::/32, upper edge
    expect_v6("2001:db8::1", false);                        // 2001:db8::/32 documentation
    expect_v6("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", false);  // documentation, upper edge
    expect_v6("2002::1", false);                            // 2002::/16 6to4
    expect_v6("2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false);  // 6to4, upper edge
    expect_v6("3ffe::1", false);                            // 3ffe::/16 6bone
    expect_v6("3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false);  // 6bone, upper edge
    expect_v6("fc00::1", false);                            // fc00::/7 ULA, lower edge
    expect_v6("fd00::1", false);                            // fc00::/7 ULA (Radiance let it through)
    expect_v6("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false);  // fc00::/7, upper edge
    expect_v6("fe80::1", false);                            // fe80::/10 link-local, lower edge
    expect_v6("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false);  // fe80::/10, upper edge
    expect_v6("fec0::1", false);                            // fec0::/10 site-local
    expect_v6("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false);  // fec0::/10, upper edge

    // IPv6 accepted (documentation addresses are rejected by design, so use
    // publicly routable ones).
    expect_v6("2606:4700:4700::1111", true);
    expect_v6("2001:4860:4860::8888", true);
    expect_v6("2a00:1450:4001:81b::200e", true);
    expect_v6("2001:db9::1", true);          // just outside 2001:db8::/32
    expect_v6("2001:100::1", true);          // just outside 2001::/32 Teredo
    expect_v6("2003::1", true);              // just outside 2002::/16
    expect_v6("fe00::1", true);              // just outside fe80::/10 and fec0::/10

    if (failures == 0) {
        std::printf("All IP validation tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d IP validation test(s) failed\n", failures);
    return 1;
}
