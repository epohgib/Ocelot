#ifndef SRC_OCELOT_H_
#define SRC_OCELOT_H_

// Copyright [2017-2026] Orpheus

#define OCELOT_VERSION_MAJOR 3
#define OCELOT_VERSION_MINOR 1
#define OCELOT_VERSION_BUGFIX 0
#define OCELOT_VERSION_NREV 1
#define OCELOT_VERSION "3.1.0-1"

#include <time.h>

#include <string>
#include <map>
#include <vector>
#include <unordered_map>
#include <set>
#include <memory>
#include <atomic>

typedef uint32_t torid_t;
typedef uint32_t userid_t;

class user;
typedef std::shared_ptr<user> user_ptr;

typedef union {
    struct {
        uint32_t addr;
        uint16_t port;
    };
    char addr_port[sizeof(uint32_t) + sizeof(uint16_t)];
} addr_port;

typedef struct {
    user_ptr user;
    int64_t uploaded;
    int64_t downloaded;
    int64_t corrupt;
    int64_t left;
    time_t last_announced;
    time_t first_announced;
    uint32_t announces;
    addr_port ap;
    bool visible;
} peer;

typedef std::map<std::string, peer> peer_list;

enum freetype { NORMAL, FREE, NEUTRAL };

typedef struct {
    torid_t id;
    uint32_t completed;
    int64_t balance;
    freetype free_torrent;
    time_t last_flushed;
    peer_list seeders;
    peer_list leechers;
    std::string last_selected_seeder;
    std::set<userid_t> tokened_users;
} torrent;

enum {
    DUPE,                // 0
    TRUMP,               // 1
    BAD_FILE_NAMES,      // 2
    BAD_FOLDER_NAMES,    // 3
    BAD_TAGS,            // 4
    BAD_FORMAT,          // 5
    DISCS_MISSING,       // 6
    DISCOGRAPHY,         // 7
    EDITED_LOG,          // 8
    INACCURATE_BITRATE,  // 9
    LOW_BITRATE,         // 10
    MUTT_RIP,            // 11
    BAD_SOURCE,          // 12
    ENCODE_ERRORS,       // 13
    BANNED,              // 14
    TRACKS_MISSING,      // 15
    TRANSCODE,           // 16
    CASSETTE,            // 17
    UNSPLIT_ALBUM,       // 18
    USER_COMPILATION,    // 19
    WRONG_FORMAT,        // 20
    WRONG_MEDIA,         // 21
    AUDIENCE             // 22
};

typedef struct {
    int reason;
    time_t time;
} del_message;

typedef struct {
    bool gzip;
    bool html;
    bool http_close;
} client_opts_t;

typedef std::unordered_map<std::string, torrent> torrent_list;
typedef std::unordered_map<std::string, user_ptr> user_list;
typedef std::unordered_map<std::string, std::string> params_type;

struct stats_t {
    std::atomic<uint32_t> open_connections;
    std::atomic<uint32_t> peak_connections;
    std::atomic<uint64_t> opened_connections;
    std::atomic<uint64_t> connection_rate;
    std::atomic<uint32_t> leechers;
    std::atomic<uint32_t> seeders;
    std::atomic<uint32_t> user_queue_size;
    std::atomic<uint32_t> torrent_queue_size;
    std::atomic<uint32_t> peer_queue_size;
    std::atomic<uint32_t> snatch_queue_size;
    std::atomic<uint32_t> token_queue_size;
    std::atomic<uint32_t> max_client_request_len;
    std::atomic<uint64_t> requests;
    std::atomic<uint64_t> request_rate;
    std::atomic<uint64_t> announcements;
    std::atomic<uint64_t> succ_announcements;
    std::atomic<uint64_t> scrapes;
    std::atomic<uint64_t> announce_duration; // all durations measure microseconds
    std::atomic<uint64_t> torrent_lock_total;
    std::atomic<uint64_t> torrent_lock_duration;
    std::atomic<uint64_t> reap_total;
    std::atomic<uint64_t> reap_lock_duration;
    std::atomic<uint64_t> reap_duration;
    std::atomic<uint64_t> bytes_read;
    std::atomic<uint64_t> bytes_written;
    std::atomic<uint64_t> auth_error_secret;
    std::atomic<uint64_t> auth_error_report;
    std::atomic<uint64_t> auth_error_announce_key;
    std::atomic<uint64_t> client_error;
    std::atomic<uint64_t> http_error;
    time_t start_time;
};
extern struct stats_t stats;

extern const char *version();
#endif  // SRC_OCELOT_H_
