#ifndef SRC_USER_H_
#define SRC_USER_H_

// Copyright [2017-2026] Orpheus

#include <atomic>

#include "ocelot.h"

class user {
 private:
    userid_t id;
    bool deleted;
    bool leechstatus;
    bool protect_ip;
    struct {
        std::atomic<uint32_t> leeching;
        std::atomic<uint32_t> seeding;
    } stats;

 public:
    user(userid_t uid, bool leech, bool protect);

    userid_t get_id() const { return id; }
    bool is_deleted() const { return deleted; }
    bool is_protected() const { return protect_ip; }
    bool can_leech() const { return leechstatus; }
    uint32_t get_leeching() const { return stats.leeching; }
    uint32_t get_seeding() const { return stats.seeding; }

    void set_deleted(bool status) { deleted = status; }
    void set_leechstatus(bool status) { leechstatus = status; }
    void set_protected(bool status) { protect_ip = status; }
    void decr_leeching() { --stats.leeching; }
    void decr_seeding() { --stats.seeding; }
    void incr_leeching() { ++stats.leeching; }
    void incr_seeding() { ++stats.seeding; }
};

#endif  // SRC_USER_H_
