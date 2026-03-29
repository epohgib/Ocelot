#ifndef SRC_WORKER_H_
#define SRC_WORKER_H_

// Copyright [2017-2026] Orpheus

#include <spdlog/spdlog.h>

#include <ctime>
#include <iostream>
#include <list>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

#include "site_comm.h"

enum tracker_status { OPEN, PAUSED, CLOSING };  // tracker status

typedef struct {
    std::string useragent;
    int64_t uploaded;
    int64_t downloaded;
    int64_t left;
    int64_t corrupt;
    bool event_completed;
    bool event_started;
    bool event_stopped;
} announce_context;

class worker {
 private:
    config * conf;
    mysql * db;
    site_comm * s_comm;
    torrent_list &torrents_list;
    user_list &users_list;
    std::vector<std::string> &whitelist;
    std::unordered_map<std::string, del_message> del_reasons;
    tracker_status status;
    bool reaper_active;
    time_t cur_time;
    std::shared_ptr<spdlog::logger> logger;
    std::mt19937 randgen;
    std::uniform_int_distribution<int> jitter;
    static std::mutex client_len_mutex;

    uint32_t announce_interval;
    uint32_t del_reason_lifetime;
    uint32_t peers_timeout;
    uint32_t numwant_limit;
    bool keepalive_enabled;
    std::string site_password;
    std::string report_password;

    std::mutex del_reasons_lock;
    void load_config(config * conf);
    void do_start_reaper();
    void reap_peers();
    void reap_del_reasons();
    peer_list::iterator add_peer(peer_list &peer_list, const peerkey_t &peer_key);

    static std::string get_del_reason(int code);

 public:
    worker(config * conf_obj, torrent_list &torrents, user_list &users, std::vector<std::string> &_whitelist, mysql * db_obj, site_comm * sc);
    void reload_config(config * conf);
    std::string work(const std::string &input, uint32_t remote_addr, client_opts_t &client_opts);
    std::string announce(const std::string &peer_id, torrent &tor, user_ptr &u, const announce_context *ctx, uint32_t numwant, const addr_port &ap, client_opts_t &client_opts);
    std::string scrape(const std::list<std::string> &infohashes, params_type &headers, client_opts_t &client_opts);
    std::string update(params_type &params, const client_opts_t &client_opts);

    void reload_lists();
    bool shutdown();

    tracker_status get_status() const { return status; }

    void start_reaper();
};

#endif  // SRC_WORKER_H_
