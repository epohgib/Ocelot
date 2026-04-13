#ifndef SRC_PEER_H_
#define SRC_PEER_H_

// Copyright [2017-2026] Orpheus

#include <atomic>

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
    addr_port ap;
    int64_t uploaded       = 0;
    int64_t downloaded     = 0;
    int64_t corrupt        = 0;
    int64_t left           = 0;
    time_t last_announced  = 0;
    time_t first_announced = 0;
    uint32_t announces     = 0;

    peer(user_ptr u, addr_port ap) : user(u), ap(ap) {}
};

#endif  // SRC_PEER_H_
