#ifndef SRC_USER_H_
#define SRC_USER_H_

// Copyright [2017-2026] Orpheus

#include <atomic>
#include <memory>
#include <string>
#include <unordered_map>

typedef uint32_t userid_t;

class user {
  private:
    userid_t id;
    bool deleted;
    bool leechstatus;
    bool protect_ip;
    bool ipv6_tracking;
    std::atomic<uint32_t> leeching;
    std::atomic<uint32_t> seeding;

  public:
    user(userid_t uid, bool leech, bool protect, bool track_ipv6) :
        id(uid),
        deleted(false),
        leechstatus(leech),
        protect_ip(protect),
        ipv6_tracking(track_ipv6),
        leeching(0),
        seeding(0)
    {}

    userid_t get_id() const { return id; }
    bool is_deleted() const { return deleted; }
    bool is_protected() const { return protect_ip; }
    bool can_leech() const { return leechstatus; }
    bool track_ipv6() const { return ipv6_tracking; }
    uint32_t get_leeching() const { return leeching; }
    uint32_t get_seeding() const { return seeding; }

    void set_deleted(bool status) { deleted = status; }
    void set_leechstatus(bool status) { leechstatus = status; }
    void set_protected(bool status) { protect_ip = status; }
    void set_track_ipv6(bool status) { ipv6_tracking = status; }

    // Applies the fields present in an update_user request. A parameter that is
    // absent leaves the corresponding field untouched: an update that only
    // carries, say, track_ipv6 must not silently drop the protection. This
    // differs from add_user, the only case where an absent visible/can_leech
    // means the default (not protected, leeching allowed).
    void apply_update(const std::unordered_map<std::string, std::string> &params) {
        auto visible_it = params.find("visible");
        auto leech_it = params.find("can_leech");
        auto track_ipv6_it = params.find("track_ipv6");
        if (visible_it != params.end()) { set_protected(visible_it->second == "0"); }
        if (leech_it != params.end()) { set_leechstatus(leech_it->second != "0"); }
        if (track_ipv6_it != params.end()) { set_track_ipv6(track_ipv6_it->second == "1"); }
    }
    void decr_leeching() { --leeching; }
    void decr_seeding()  { --seeding;  }
    void incr_leeching() { ++leeching; }
    void incr_seeding()  { ++seeding;  }
};

typedef std::shared_ptr<user> user_ptr;

#endif  // SRC_USER_H_
