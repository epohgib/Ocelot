#ifndef SRC_USER_H_
#define SRC_USER_H_

// Copyright [2017-2026] Orpheus

#include <atomic>
#include <memory>

typedef uint32_t userid_t;

class user {
  private:
    userid_t id;
    bool deleted;
    bool leechstatus;
    bool protect_ip;
    std::atomic<uint32_t> leeching;
    std::atomic<uint32_t> seeding;

  public:
    user(userid_t uid, bool leech, bool protect) :
        id(uid),
        deleted(false),
        leechstatus(leech),
        protect_ip(protect),
        leeching(0),
        seeding(0)
    {}

    userid_t get_id() const { return id; }
    bool is_deleted() const { return deleted; }
    bool is_protected() const { return protect_ip; }
    bool can_leech() const { return leechstatus; }
    uint32_t get_leeching() const { return leeching; }
    uint32_t get_seeding() const { return seeding; }

    void set_deleted(bool status) { deleted = status; }
    void set_leechstatus(bool status) { leechstatus = status; }
    void set_protected(bool status) { protect_ip = status; }
    void decr_leeching() { --leeching; }
    void decr_seeding()  { --seeding;  }
    void incr_leeching() { ++leeching; }
    void incr_seeding()  { ++seeding;  }
};

typedef std::shared_ptr<user> user_ptr;

#endif  // SRC_USER_H_
