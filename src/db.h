#ifndef SRC_DB_H_
#define SRC_DB_H_

// Copyright [2017-2026] Orpheus

#pragma GCC visibility push(default)

#include <mysql++/mysql++.h>
#include <spdlog/spdlog.h>
#include <string>
#include <unordered_map>
#include <queue>
#include <memory>
#include <vector>
#include "config.h"

class mysql {
 private:
    mysqlpp::Connection conn;

    std::string heavy_peer_buffer;
    std::string light_peer_buffer;
    std::string snatch_buffer;
    std::string token_buffer;
    std::string torrent_buffer;
    std::string user_buffer;

    std::queue<std::string> peer_queue;
    std::queue<std::string> snatch_queue;
    std::queue<std::string> token_queue;
    std::queue<std::string> torrent_queue;
    std::queue<std::string> user_queue;

    std::string mysql_db, mysql_host, mysql_username, mysql_password;
    unsigned int mysql_port;
    bool u_active, t_active, p_active, s_active, tok_active;
    bool readonly;

    // These locks prevent more than one thread from reading/writing the buffers.
    // These should be held for the minimum time possible.
    std::mutex peer_buffer_lock;
    std::mutex snatch_buffer_lock;
    std::mutex token_buffer_lock;
    std::mutex torrent_buffer_lock;
    std::mutex user_buffer_lock;

    std::mutex peer_queue_lock;
    std::mutex snatch_queue_lock;
    std::mutex token_queue_lock;
    std::mutex torrent_queue_lock;
    std::mutex user_queue_lock;

    std::shared_ptr<spdlog::logger> logger;

    void load_config(config * conf);
    void load_tokens(torrent_list &torrents);
    mysqlpp::Connection create_connection();

    std::string escape(const std::string &value);
    void do_flush_users();
    void do_flush_torrents();
    void do_flush_snatches();
    void do_flush_peers();
    void do_flush_tokens();

    void flush_users();
    void flush_torrents();
    void flush_snatches();
    void flush_peers();
    void flush_tokens();
    void clear_peer_data();

 public:
    bool verbose_flush;

    mysql(config * conf);
    void reload_config(config * conf);
    void flush();
    bool connected();
    bool all_clear() const;
    void load_torrents(torrent_list &torrents);
    void load_users(user_list &users);
    void load_whitelist(std::vector<std::string> &whitelist);
    
    void record_peer(
        const userid_t user_id,
        const torid_t torrent_id,
        const bool active,
        const int64_t uploaded,
        const int64_t downloaded,
        const int64_t upspeed,
        const int64_t downspeed,
        const int64_t left,
        const int64_t corrupt,
        const uint32_t seed_time,
        const uint32_t announces,
        const std::string &addr,
        const std::string &peer_id,
        const std::string &useragent
    );

    void record_peer(
        const userid_t user_id,
        const torid_t torrent_id,
        const uint32_t seed_time,
        const uint32_t announces,
        const std::string &peer_id
    );

    void record_snatch(
        const userid_t user_id,
        const torid_t torrent_id,
        const std::string &addr
    );

    void record_token(
        const userid_t user_id,
        const torid_t torrent_id,
        const int64_t downloaded_change
    );

    void record_torrent(
        const torid_t torrent_id,
        const uint32_t seeder_total,
        const uint32_t leecher_total,
        const bool completed,
        const int64_t balance
    );

    void record_user(
        const userid_t user_id,
        const int64_t uploaded_change,
        const int64_t downloaded_change
    );

    std::mutex torrent_list_mutex;
    std::mutex user_list_mutex;
    std::mutex whitelist_mutex;
};

#pragma GCC visibility pop

#endif  // SRC_DB_H_
