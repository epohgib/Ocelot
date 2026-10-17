#ifndef SRC_PEER_H_
#define SRC_PEER_H_

// Copyright [2017-2026] Orpheus

#include <atomic>
#include <string>
#include <utility>

#include "user.h"
#include "xxhash.hpp"

typedef union {
    struct {
        uint32_t addr;
        uint16_t port;
    };
    char addr_port[sizeof(uint32_t) + sizeof(uint16_t)];
} addr_port;

class peer {
  public:
    user_ptr user;
    addr_port ap;              // IPv4 endpoint, 6 compact bytes (valid only if has_ipv4)
    bool has_ipv4 = false;     // `ap` is a raw union with no empty state
    std::string ipv6;          // 16 network-order bytes of in6_addr, "" if absent
    std::string ipv6_port;     // 18 compact bytes: 16 address bytes + 2 port bytes
    int64_t uploaded       = 0;
    int64_t downloaded     = 0;
    int64_t corrupt        = 0;
    int64_t left           = 0;
    time_t last_announced  = 0;
    time_t first_announced = 0;
    uint32_t announces     = 0;

    peer(user_ptr u, addr_port ap, bool has_ipv4, std::string ipv6, std::string ipv6_port)
        : user(u), ap(ap), has_ipv4(has_ipv4), ipv6(std::move(ipv6)), ipv6_port(std::move(ipv6_port)) {}
};

#endif  // SRC_PEER_H_
