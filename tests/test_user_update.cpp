// Unit tests for user::apply_update(), i.e. the update_user parameter
// semantics: an absent parameter must leave the field untouched.
// Built as the `test_user_update` target and run with `ctest` (see
// CMakeLists.txt).

#include <cstdio>
#include <unordered_map>

#include "user.h"

namespace {

int failures = 0;

typedef std::unordered_map<std::string, std::string> params_type;

void expect(const char *what, bool actual, bool expected) {
    if (actual != expected) {
        std::fprintf(stderr, "FAIL: %s is %s, expected %s\n", what,
                     actual ? "true" : "false",
                     expected ? "true" : "false");
        failures++;
    }
}

// The fixture is a user that is both protected and allowed to leech, so any
// field an update does not carry must survive it.
user make_user() {
    return user(1, true, true, false);
}

}  // namespace

int main() {
    // Only track_ipv6 present: protection and leeching must not change.
    {
        user u = make_user();
        u.apply_update(params_type{{"passkey", "p"}, {"track_ipv6", "1"}});
        expect("track_ipv6-only keeps protect", u.is_protected(), true);
        expect("track_ipv6-only keeps can_leech", u.can_leech(), true);
        expect("track_ipv6-only sets track_ipv6", u.track_ipv6(), true);
    }

    // Only can_leech present: protection must not change.
    {
        user u = make_user();
        u.apply_update(params_type{{"passkey", "p"}, {"can_leech", "0"}});
        expect("can_leech-only keeps protect", u.is_protected(), true);
        expect("can_leech-only blocks leech", u.can_leech(), false);
    }

    // Only visible present: leeching must not change.
    {
        user u = make_user();
        u.apply_update(params_type{{"passkey", "p"}, {"visible", "0"}});
        expect("visible=0 protects", u.is_protected(), true);
        expect("visible-only keeps can_leech", u.can_leech(), true);
    }
    {
        user u = make_user();
        u.apply_update(params_type{{"visible", "1"}});
        expect("visible=1 unprotects", u.is_protected(), false);
    }

    {
        user u = user(1, false, true, true);
        u.apply_update(params_type{{"can_leech", "1"}});
        expect("can_leech=1 allows leech", u.can_leech(), true);
    }
    {
        user u = user(1, false, true, true);
        u.apply_update(params_type{{"track_ipv6", "0"}});
        expect("track_ipv6=0 revokes", u.track_ipv6(), false);
    }

    // An update with no known parameter at all (e.g. the site sending only the
    // passkey) changes nothing.
    {
        user u = make_user();
        u.apply_update(params_type{{"passkey", "p"}});
        expect("empty update keeps protect", u.is_protected(), true);
        expect("empty update keeps can_leech", u.can_leech(), true);
        expect("empty update keeps track_ipv6", u.track_ipv6(), false);
    }

    if (failures) {
        std::fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    std::printf("all user update cases passed\n");
    return 0;
}
