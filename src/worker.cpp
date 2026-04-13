// Copyright [2017-2026] Orpheus

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <thread>
#include <utility>

#include "ocelot.h"
#include "config.h"
#include "db.h"
#include "worker.h"
#include "misc_functions.h"
#include "site_comm.h"
#include "response.h"
#include "report.h"

std::mutex worker::client_len_mutex;

const uint64_t xxh_seed = []() {
    std::random_device rd;
    return rd();
}();

//---------- Worker - does stuff with input
worker::worker(
    config * conf_obj,
    torrent_list &torrents,
    user_list &users,
    std::vector<std::string> &_whitelist,
    mysql * db_obj,
    site_comm * sc
) :
    conf(conf_obj),
    db(db_obj),
    s_comm(sc),
    torrents_list(torrents),
    users_list(users),
    whitelist(_whitelist),
    status(OPEN),
    reaper_active(false),
    logger(spdlog::get("logger")),
    randgen((std::random_device())()
) {
    load_config(conf);
}

void worker::load_config(config * conf) {
    announce_interval   = conf->get_uint("announce_interval");
    del_reason_lifetime = conf->get_uint("del_reason_lifetime");
    peers_timeout       = conf->get_uint("peers_timeout");
    numwant_limit       = conf->get_uint("numwant_limit");
    keepalive_enabled   = conf->get_uint("keepalive_timeout") != 0;
    site_password       = conf->get_str("site_password");
    report_password     = conf->get_str("report_password");
    jitter              = std::uniform_int_distribution<int>(0, conf->get_uint("announce_jitter"));
}

void worker::reload_config(config * conf) {
    load_config(conf);
}

void worker::reload_lists() {
    status = PAUSED;
    db->load_torrents(torrents_list);
    db->load_users(users_list);
    db->load_whitelist(whitelist);
    status = OPEN;
}

bool worker::shutdown() {
    if (status == OPEN) {
        status = CLOSING;
        logger->info("closing tracker... press Ctrl-C again to terminate");
        return false;
    }
    if (status == CLOSING) {
        logger->info("shutting down uncleanly");
        return true;
    }
    return false;
}

std::string worker::work(const std::string &input, uint32_t remote_addr, client_opts_t &client_opts) {
    unsigned int input_length = input.length();

    //---------- Parse request - ugly but fast. Using substr exploded.
    if (input_length < 60) {  // Way too short to be anything useful
        stats.http_error++;
        return error("GET string too short", client_opts);
    }

    if (input[37] != '/') {
        stats.http_error++;
        return error("Malformed announce", client_opts);
    }

    std::string passkey(input.substr(5, 32));
    size_t pos = 38;

    // Get the action
    enum action_t {
        INVALID = 0, ANNOUNCE, SCRAPE, UPDATE, REPORT
    };
    action_t action = INVALID;

    switch (input[pos]) {
        case 'a':
            stats.announcements++;
            action = ANNOUNCE;
            pos += 8;
            break;
        case 's':
            stats.scrapes++;
            action = SCRAPE;
            pos += 6;
            break;
        case 'u':
            action = UPDATE;
            pos += 6;
            break;
        case 'r':
            action = REPORT;
            pos += 6;
            break;
    }

    unsigned int max_len_increased = false;
    {
        const std::lock_guard<std::mutex> lock(worker::client_len_mutex);
        unsigned int max_len = stats.max_client_request_len;
        if (max_len < input_length) {
            stats.max_client_request_len = input_length;
            max_len_increased = true;
        }
    }
    if (max_len_increased) {
        logger->info(
            "max client request length raised to {} on action {}",
            input_length, (int)action
        );
    }

    if (input[pos] != '?') {
        // No parameters given. Probably means we're not talking to a torrent client
        client_opts.html = true;
        return http_response("Nothing to see here", client_opts);
    }

    // Parse URL params
    std::list<std::string> infohashes;  // For scrape only

    params_type params;
    std::string key;
    std::string value;
    bool parsing_key = true;  // true = key, false = value

    ++pos;  // Skip the '?'
    for (; pos < input_length; ++pos) {
        if (input[pos] == '=') {
            parsing_key = false;
        } else if (input[pos] == '&' || input[pos] == ' ') {
            parsing_key = true;
            if (action == SCRAPE && key == "info_hash") {
                infohashes.push_back(value);
            } else {
                params[key] = value;
            }
            key.clear();
            value.clear();
            if (input[pos] == ' ') {
                break;
            }
        } else {
            if (parsing_key) {
                key.push_back(input[pos]);
            } else {
                value.push_back(input[pos]);
            }
        }
    }
    ++pos;

    if (input.compare(pos, 5, "HTTP/") != 0) {
        stats.http_error++;
        return error("Malformed HTTP request", client_opts);
    }

    std::string http_version;
    pos += 5;
    while (input[pos] != '\r' && input[pos] != '\n') {
        http_version.push_back(input[pos]);
        ++pos;
    }
    ++pos;  // skip line break - should probably be += 2, but just in case a client doesn't send \r

    // Parse headers
    params_type headers;
    parsing_key = true;
    bool found_data = false;

    for (; pos < input_length; ++pos) {
        if (input[pos] == ':') {
            parsing_key = false;
            ++pos;  // skip space after :
        } else if (input[pos] == '\n' || input[pos] == '\r') {
            parsing_key = true;

            if (found_data) {
                found_data = false;  // dodge for getting around \r\n or just \n
                std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                headers[key] = value;
                key.clear();
                value.clear();
            }
        } else {
            found_data = true;
            if (parsing_key) {
                key.push_back(input[pos]);
            } else {
                value.push_back(input[pos]);
            }
        }
    }

    if (keepalive_enabled) {
        auto hdr_http_close = headers.find("connection");
        if (hdr_http_close == headers.end()) {
            client_opts.http_close = (http_version == "1.0");
        } else {
            client_opts.http_close = (hdr_http_close->second != "Keep-Alive");
        }
    } else {
        client_opts.http_close = true;
    }

    cur_time = time(NULL);
    if (status != OPEN) {
        return error("the tracker is not accepting connections", client_opts);
    } else if (action == INVALID) {
        stats.http_error++;
        return error("invalid action", client_opts);
    } else if (action == UPDATE) {
        if (passkey != site_password) {
            stats.auth_error_secret++;
            logger->error("incorrect TRACKER_SECRET received");
            return error("authentication failure", client_opts);
        }
        return update(params, client_opts);
    } else if (action == REPORT) {
        if (passkey != report_password) {
            stats.auth_error_report++;
            logger->error("incorrect TRACKER_REPORT received");
            return error("authentication failure", client_opts);
        }

        std::string report_action(params["get"]);
        if (report_action == "prom_stats") {
            // exclude per-arena (a), destroyed merged (d), mutex (m) and extents (e) statistics
            std::string jemalloc_stats(report_jemalloc_plain("adex", conf->get_str("report_path")));
            return http_response(
                report_prom_stats(jemalloc_stats.c_str()),
                client_opts
            );
        } else if (report_action == "stats") {
            return http_response(
                report(announce_interval, conf->get_uint("announce_jitter")),
                client_opts
            );
        } else if (report_action == "jemalloc") {
            return http_response(
                report_jemalloc_plain("adex", conf->get_str("report_path")),
                client_opts
            );
        } else if (report_action == "torrent") {
            std::string infohash = params["info_hash"];
            if (infohash.empty()) {
                stats.auth_error_report++;
                logger->error("torrent report with no infohash");
                return error("Infohash missing", client_opts);
            }
            std::string info_hash_decoded = hex_decode(params["info_hash"]);
            torrent t;
            bool found = false;
            {
                std::lock_guard<std::mutex> tl_lock(db->torrent_list_mutex);
                auto it = torrents_list.find(info_hash_decoded);
                if (it != torrents_list.end()) {
                    t = it->second;
                    found = true;
                }
            }
            if (!found) {
                stats.auth_error_report++;
                logger->error("torrent infohash not found");
                return error("Infohash not found", client_opts);
            }
            return http_response(
                report_torrent(t),
                client_opts
            );
        } else if (report_action == "user") {
            std::string announce_key = params["key"];
            if (announce_key.empty()) {
                stats.auth_error_announce_key++;
                logger->error("user report with no announce key");
                return error("Announce key missing", client_opts);
            }
            user_ptr u;
            {
                // lock scope
                std::lock_guard<std::mutex> ul_lock(db->user_list_mutex);
                auto user_it = users_list.find(announce_key);
                if (user_it == users_list.end()) {
                    stats.auth_error_announce_key++;
                    logger->error("user report announce key not found");
                    return error("Announce key not found", client_opts);
                }
                u = user_it->second;
            }
            return http_response(
                report_user(u),
                client_opts
            );
        }

        stats.http_error++;
        logger->error("unrecognized report query");
        return error("unrecognized report query", client_opts);
    }

    // Either a scrape or an announce, find the user
    user_ptr u;
    {
        // lock scope
        std::lock_guard<std::mutex> ul_lock(db->user_list_mutex);
        auto user_it = users_list.find(passkey);
        if (user_it == users_list.end()) {
            stats.auth_error_announce_key++;
            return error("Passkey not found", client_opts);
        }
        u = user_it->second;
    }

    if (action == SCRAPE) {
        return scrape(infohashes, headers, client_opts);
    }

    if (params["compact"] != "1") {
        stats.client_error++;
        return error("Your client does not support compact announces", client_opts);
    }

    params_type::const_iterator peer_id_iterator = params.find("peer_id");
    if (peer_id_iterator == params.end()) {
        stats.client_error++;
        return error("No peer ID", client_opts);
    }
    const std::string peer_id = hex_decode(peer_id_iterator->second);
    if (peer_id.length() != 20) {
        stats.client_error++;
        return error("Invalid peer ID ", client_opts);
    }

    // If we are behind a forward proxy, trust the X-Forwarded-For header
    // and replace the remote address (unless configured not to).
    if (!conf->get_bool("ignore_xff")) {
        auto it = headers.find("x-forwarded-for");
        if (it != headers.end()) {
            std::string ip = it->second;
            size_t comma_pos = ip.find(',');
            if (comma_pos != std::string::npos) {
                ip.resize(comma_pos); // truncate before first comma
            }
            struct sockaddr_in sa;
            if (!inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr))) {
                return error(
                    "failed to parse X-Forwarded-For: "
                    // we received garbage, so avoid pwning anybody
                    + bintohex(ip),
                    client_opts
                );
            };
            remote_addr = sa.sin_addr.s_addr;
        }
    }

    // Trust the port given by the client.
    // If it is incorrect, they will not be connectable. Too bad for them.
    uint16_t remote_port;
    {
        auto port_it = params.find("port");
        if (port_it == params.end()) {
            return error("no client port parsed from GET", client_opts);
        }
        std::string param = port_it->second;
        auto [ptr, ec] = std::from_chars(param.data(), param.data() + param.size(), remote_port);
        if (ec != std::errc()) {
            return error("client port value out of range", client_opts);
        }
    }
    addr_port ap = {remote_addr, htons(remote_port)};

    // Let's translate the infohash into something nice
    // info_hash is a url encoded (hex) base 20 number
    std::string info_hash_decoded = hex_decode(params["info_hash"]);

    // how many peers are wanted for this announce?
    uint32_t numwant;
    auto param_numwant = params.find("numwant");
    if (param_numwant == params.end()) {
        numwant = numwant_limit;
    } else {
        numwant = std::min((int32_t)numwant_limit, strtoint32(param_numwant->second));
    }

    std::string useragent(headers["user-agent"]);
    if (useragent.length() > 51) {
        useragent.resize(51);
    }
    announce_context ctx = {
        useragent,
        std::max((int64_t)0, strtoint64(params["uploaded"])),
        std::max((int64_t)0, strtoint64(params["downloaded"])),
        std::max((int64_t)0, strtoint64(params["left"])),
        std::max((int64_t)0, strtoint64(params["corrupt"])),
        params["event"] == "completed",
        params["event"] == "started",
        params["event"] == "stopped"
    };

    // lock the torrent list from here until the end of the announce processing
    std::chrono::steady_clock::time_point lock_begin = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> tl_lock(db->torrent_list_mutex);
    stats.torrent_lock_duration.fetch_add(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - lock_begin
        ).count()
    );
    stats.torrent_lock_total++;

    auto tor = torrents_list.find(info_hash_decoded);
    if (tor == torrents_list.end()) {
        std::lock_guard<std::mutex> dr_lock(del_reasons_lock);
        auto msg = del_reasons.find(info_hash_decoded);
        if (msg != del_reasons.end() && msg->second.reason != -1) {
            return error("Unregistered torrent: " + get_del_reason(msg->second.reason), client_opts);
        } else {
            return error("Unregistered torrent", client_opts);
        }
    }

    std::unique_lock<std::mutex> wl_lock(db->whitelist_mutex);
    if (whitelist.size() > 0) {
        bool found = false;  // Found client in whitelist?
        for (const std::string& prefix : whitelist) {
            if (peer_id.compare(0, prefix.length(), prefix) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            stats.client_error++;
            return error("Your client is not on the whitelist", client_opts);
        }
    }
    wl_lock.unlock();

    return announce(peer_id, tor->second, u, &ctx, numwant, ap, client_opts);
}

std::string worker::announce(
    const std::string &peer_id,
    torrent &tor,
    user_ptr &u,
    const announce_context *ctx,
    uint32_t numwant,
    const addr_port &ap,
    const client_opts_t &client_opts
) {
    std::chrono::steady_clock::time_point announce_begin = std::chrono::steady_clock::now();

    int active = 1;                  // This is the value that marks a peer as active/inactive in the database
    bool inserted = false;           // If we insert the peer as opposed to update
    bool update_torrent = false;     // Whether or not we should update the torrent in the DB
    bool completed_torrent = false;  // Whether or not the current announcement is a snatch
    bool expire_token = false;       // Whether or not to expire a token after torrent completion
    bool peer_changed = false;       // Whether or not the peer is new or has changed since the last announcement
    userid_t userid = u->get_id();

    logger->debug("announce: tor={} user={} up={} down={} left={} corrupt={}", tor.id, userid, ctx->uploaded, ctx->downloaded, ctx->left, ctx->corrupt);

    xxh::hash_state_t<64> state(xxh_seed);
    state.update(peer_id);
    state.update(ap.addr_port, sizeof(ap.addr_port));
    state.update(&userid, sizeof(userid_t));
    const peerkey_t peer_key = state.digest();

    if (ctx->event_completed) {
        // Don't update <snatched> here as we may decide to use other conditions later on
        completed_torrent = (ctx->left == 0);  // Sanity check just to be extra safe
    } else if (ctx->event_stopped) {
        peer_changed = true;
        update_torrent = true;
        active = 0;
    }

    peer * p;
    peer_list::iterator peer_it;
    // Insert/find the peer in the torrent list
    if (ctx->left > 0) {
        peer_it = tor.leechers.find(peer_key);
        if (peer_it == tor.leechers.end()) {
            // Check if peer is in seeders (e.g., seeder re-announcing with ctx->left > 0)
            peer_it = tor.seeders.find(peer_key);
            if (peer_it != tor.seeders.end()) {
                peer_it = worker::move_seeder_to_leecher(tor, u, peer_it, peer_key);
                peer_changed = true;
            } else {
                peer_it = worker::add_leecher(tor, u, ap, peer_key);
                inserted = true;
            }
        }
    } else if (completed_torrent) {
        peer_it = tor.leechers.find(peer_key);
        if (peer_it == tor.leechers.end()) {
            peer_it = tor.seeders.find(peer_key);
            if (peer_it == tor.seeders.end()) {
                peer_it = worker::add_seeder(tor, u, ap, peer_key);
                inserted = true;
            } else {
                // Already a seeder, not a real completion
                completed_torrent = false;
            }
        } else {
            // Peer is in leechers - check if also incorrectly in seeders
            auto seeder_it = tor.seeders.find(peer_key);
            if (seeder_it != tor.seeders.end()) {
                // Peer is in both lists (invalid state) - remove from seeders
                // since they're completing as a leecher, they should only be in leechers
                // until we move them to seeders below
                worker::remove_seeder(tor, u, seeder_it);
            }
        }
    } else {
        peer_it = tor.seeders.find(peer_key);
        if (peer_it == tor.seeders.end()) {
            peer_it = tor.leechers.find(peer_key);
            if (peer_it == tor.leechers.end()) {
                peer_it = worker::add_seeder(tor, u, ap, peer_key);
                inserted = true;
            } else {
                peer_it = worker::move_leecher_to_seeder(tor, u, peer_it, peer_key);
                peer_changed = true;
            }
        }
    }
    p = &peer_it->second;

    int64_t upspeed = 0;
    int64_t downspeed = 0;
    if (inserted || ctx->event_started) {
        // New peer on this torrent (maybe)
        update_torrent = true;
        if (inserted) {
            // If this was an existing peer, the user pointer will be corrected later
            p->user = u;
        }
        p->first_announced = cur_time;
        p->last_announced = 0;
        p->uploaded = ctx->uploaded;
        p->downloaded = ctx->downloaded;
        p->corrupt = ctx->corrupt;
        p->announces = 1;
        peer_changed = true;
    } else if (ctx->uploaded < p->uploaded || ctx->downloaded < p->downloaded) {
        p->announces++;
        p->uploaded = ctx->uploaded;
        p->downloaded = ctx->downloaded;
        peer_changed = true;
    } else {
        int64_t uploaded_change = 0;
        int64_t downloaded_change = 0;
        int64_t corrupt_change = 0;
        p->announces++;

        if (ctx->uploaded != p->uploaded) {
            uploaded_change = ctx->uploaded - p->uploaded;
            p->uploaded = ctx->uploaded;
        }
        if (ctx->downloaded != p->downloaded) {
            downloaded_change = ctx->downloaded - p->downloaded;
            p->downloaded = ctx->downloaded;
        }
        if (ctx->corrupt != p->corrupt) {
            corrupt_change = ctx->corrupt - p->corrupt;
            p->corrupt = ctx->corrupt;
            tor.balance -= corrupt_change;
            update_torrent = true;
        }
        peer_changed = peer_changed || uploaded_change || downloaded_change || corrupt_change;

        if (uploaded_change || downloaded_change) {
            tor.balance += uploaded_change;
            tor.balance -= downloaded_change;
            update_torrent = true;

            if (cur_time > p->last_announced) {
                // Note: the db stores speed values as 32 bits (which saves a lot of space).
                // Therefore, clamp speeds to 2**31 - 1. The only time this ever matters is
                // when there is a large change between two announces in very quick succession,
                // which is probably bogus in any event.
                auto delta = cur_time - p->last_announced;
                auto max   = std::numeric_limits<int32_t>::max();
                upspeed    = (uploaded_change / delta   > max) ? max : uploaded_change / delta;
                downspeed  = (downloaded_change / delta > max) ? max : downloaded_change / delta;
            }
            auto sit = tor.tokened_users.find(userid);
            if (tor.free_torrent == NEUTRAL) {
                downloaded_change = 0;
                uploaded_change = 0;
            } else if (tor.free_torrent == FREE || sit != tor.tokened_users.end()) {
                if (sit != tor.tokened_users.end()) {
                    expire_token = true;
                    db->record_token(userid, tor.id, downloaded_change);
                }
                downloaded_change = 0;
            }

            if (uploaded_change || downloaded_change) {
                db->record_user(userid, uploaded_change, downloaded_change);
            }
        }
    }
    p->left = ctx->left;

    // Update the remote address if their ISP reassigned a new address in the interval
    if (memcmp(&ap.addr_port, &p->ap.addr_port, sizeof(ap.addr_port)) != 0) {
        p->ap = ap;
    }

    // Update the peer
    p->last_announced = cur_time;

    // Add peer data to the database
    if (peer_changed) {
        db->record_peer(
            userid, tor.id, active,
            ctx->uploaded, ctx->downloaded, upspeed, downspeed, ctx->left, ctx->corrupt,
            cur_time - p->first_announced, p->announces,
            u->is_protected() ? "''" : "inet_ntoa(" + std::to_string(ntohl(ap.addr)) + ')',
            peer_id, ctx->useragent
        );
    } else {
        db->record_peer(
            userid, tor.id, cur_time - p->first_announced, p->announces, peer_id
        );
    }

    if (ctx->event_stopped) {
        numwant = 0;
    } else if (ctx->left > 0 &&!u->can_leech() ) {
        numwant = 0;
    } else if (completed_torrent) {
        update_torrent = true;
        tor.completed++;

        db->record_snatch(
            userid,
            tor.id,
            u->is_protected() ? "''" : "inet_ntoa(" + std::to_string(ntohl(ap.addr)) + ')'
        );

        // User is a seeder now!
        if (!inserted) {
            p = worker::insert_seeder(tor, u, peer_it, peer_key);
        }
        if (expire_token) {
            s_comm->expire_token(tor.id, userid);
            tor.tokened_users.erase(userid);
        }
    }

    std::string peers;
    if (numwant > 0) {
        logger->debug(
            "announce: tor={} user={} left={} want={}",
            tor.id, userid, ctx->left, numwant
        );
        peers.reserve(numwant * sizeof(ap.addr_port));
        if (ctx->left > 0) {
            // first show  seeders to a leecher
            if (tor.seeders.size() <= numwant) {
                // send all of them
                numwant -= tor.seeders.size();
                for (const auto &it : tor.seeders) {
                    auto user = it.second.user;
                    logger->debug(
                        "announce: tor={} user={} direct seeder={}",
                        tor.id, userid, user->get_id()
                    );
                    if (
                        !user->is_deleted()
                        && !user->is_protected()
                        && user->get_id() != userid
                    ) {
                        peers.append(it.second.ap.addr_port, sizeof(ap.addr_port));
                    }
                }
            } else {
                // round-robin selection of least recently offered seeders
                auto it = tor.seeders.upper_bound(tor.last_selected_seeder);
                auto start = it;
                while (numwant > 0) {
                    if (it == tor.seeders.end()) {
                        it = tor.seeders.begin();
                    }
                    logger->debug(
                        "announce: tor={} user={} round-robin seeder={}",
                        tor.id, userid, it->second.user->get_id()
                    );
                    if (
                        !it->second.user->is_deleted()
                        && !it->second.user->is_protected()
                        && it->second.user->get_id() != userid
                    ) {
                        peers.append(it->second.ap.addr_port, sizeof(ap.addr_port));
                        tor.last_selected_seeder = it->first;
                        --numwant;
                    }
                    if (++it == start) {
                        break; // wrapped around: no more seeders available
                    }
                }
            }
        }
        // whether client is leecher or seeder,
        // add leechers until we have a full complement of peers
        if (numwant > 0 && !tor.leechers.empty()) {
            peer_list::const_iterator it = tor.leechers.begin();
            while (numwant > 0 && it != tor.leechers.end()) {
                logger->debug(
                    "announce: tor={} user={} leecher={}",
                    tor.id, userid, it->second.user->get_id()
                );
                // Don't show users themselves or leech disabled users
                if (
                    !it->second.user->is_deleted()
                    && it->second.user->can_leech()
                    && it->second.user->get_id() != userid
                ) {
                    peers.append(it->second.ap.addr_port, sizeof(ap.addr_port));
                    --numwant;
                }
                ++it;
            }
        }
    }

    // Update the stats
    stats.succ_announcements++;

    // Correct the stats for the old user if the peer's user link has changed (really?)
    if (p->user != u) {
        // How often does this happen?
        logger->error(
            "peer user changed from {} to {} via {}:{}",
            p->user->get_id(), u->get_id(), ap.addr, ap.port
        );
        p->user = u;
    }

    // Remove peers as late as possible to prevent access problems.
    if (ctx->event_stopped) {
        if (ctx->left > 0) {
            tor.leechers.erase(peer_it);
            stats.leechers--;
            u->decr_leeching();
        } else {
            tor.seeders.erase(peer_it);
            stats.seeders--;
            u->decr_seeding();
        }
    }

    // Putting this after the peer deletion gives us accurate swarm sizes
    if (update_torrent || tor.last_flushed + 3600 < cur_time) {
        tor.last_flushed = cur_time;
        db->record_torrent(
            tor.id, tor.seeders.size(), tor.leechers.size(), (completed_torrent ? 1 : 0), tor.balance
        );
    }

    if (!u->can_leech() && ctx->left > 0) {
        stats.announce_duration.fetch_add(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - announce_begin
            ).count()
        );
        return error("Access denied, leeching forbidden", client_opts);
    }

    std::string output;
    output.reserve(350);
    fmt::format_to(std::back_inserter(output),
        "d8:completei{}"
        "e10:downloadedi{}"
        "e10:incompletei{}"
        "e8:intervali{}"
        "e12:min intervali{}"
        "e5:peers{}:{}e",
        tor.seeders.size(),
        tor.completed,
        tor.leechers.size(),
        announce_interval + jitter(randgen),
        announce_interval,
        peers.length(), peers
    );
    logger->debug("announce: tor={} user={} peer({}) response({})", tor.id, userid, bintohex(peers), output);

    /* gzip compression actually makes announce returns larger from our
     * testing. Feel free to enable this here if you'd like but be aware of
     * possibly inflated return size
     */
    /*if (headers["accept-encoding"].find("gzip") != std::string::npos) {
        client_opts.gzip = true;
    }*/

    stats.announce_duration.fetch_add(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - announce_begin
        ).count()
    );
    return http_response(output, client_opts);
}

std::string worker::scrape(const std::list<std::string> &infohashes, params_type &headers, client_opts_t &client_opts) {
    std::string output;
    output.reserve(300);
    output= "d5:filesd";
    for (std::list<std::string>::const_iterator i = infohashes.begin(); i != infohashes.end(); ++i) {
        std::string infohash(hex_decode(*i));

        torrent_list::iterator tor = torrents_list.find(infohash);
        if (tor == torrents_list.end()) {
            continue;
        }
        torrent *t = &(tor->second);

        output += fmt::format(
            "{}:{}"
            "d8:completei{}"
            "e10:incompletei{}"
            "e10:downloadedi{}ee",
            infohash.length(), infohash,
            t->seeders.size(),
            t->leechers.size(),
            t->completed
        );
    }
    output += "ee";
    if (headers["accept-encoding"].find("gzip") != std::string::npos) {
        client_opts.gzip = true;
    }
    return http_response(output, client_opts);
}

// TODO: Restrict to local IPs
std::string worker::update(params_type &params, const client_opts_t &client_opts) {
    std::string action(params["action"]);
    if (action == "change_passkey") {
        std::string oldpasskey = params["oldpasskey"];
        std::string newpasskey = params["newpasskey"];
        std::lock_guard<std::mutex> ul_lock(db->user_list_mutex);
        auto u = users_list.find(oldpasskey);
        if (u == users_list.end()) {
            logger->warn(
                "no user with passkey {} exists when attempting to change passkey to {}",
                oldpasskey, newpasskey
            );
        } else {
            users_list[newpasskey] = u->second;
            users_list.erase(oldpasskey);
            logger->info(
                "changed passkey from {} to {} for user {}",
                oldpasskey, newpasskey, u->second->get_id()
            );
        }
    } else if (action == "add_torrent") {
        torrent *t;
        std::string info_hash = params["info_hash"];
        info_hash = hex_decode(info_hash);
        std::lock_guard<std::mutex> tl_lock(db->torrent_list_mutex);
        auto i = torrents_list.find(info_hash);
        if (i == torrents_list.end()) {
            t = &torrents_list[info_hash];
            t->id = static_cast<torid_t>(strtoint32(params["id"]));
            t->balance = 0;
            t->completed = 0;
            t->last_selected_seeder = 0;
        } else {
            t = &i->second;
        }
        if (params["freetorrent"] == "0") {
            t->free_torrent = NORMAL;
        } else if (params["freetorrent"] == "1") {
            t->free_torrent = FREE;
        } else {
            t->free_torrent = NEUTRAL;
        }
        logger->info("added torrent {}", t->id);
    } else if (action == "update_torrent") {
        std::string info_hash = params["info_hash"];
        info_hash = hex_decode(info_hash);
        freetype fl;
        if (params["freetorrent"] == "0") {
            fl = NORMAL;
        } else if (params["freetorrent"] == "1") {
            fl = FREE;
        } else {
            fl = NEUTRAL;
        }
        std::lock_guard<std::mutex> tl_lock(db->torrent_list_mutex);
        auto torrent_it = torrents_list.find(info_hash);
        if (torrent_it != torrents_list.end()) {
            torrent_it->second.free_torrent = fl;
            logger->info("updated torrent {} to FL {}", torrent_it->second.id, (int)fl);
        } else {
            logger->warn("failed to find torrent {} to FL {}", info_hash, (int)fl);
        }
    } else if (action == "update_torrents") {
        // Each decoded infohash is exactly 20 characters long.
        std::string info_hashes = params["info_hashes"];
        info_hashes = hex_decode(info_hashes);
        freetype fl;
        if (params["freetorrent"] == "0") {
            fl = NORMAL;
        } else if (params["freetorrent"] == "1") {
            fl = FREE;
        } else {
            fl = NEUTRAL;
        }
        std::lock_guard<std::mutex> tl_lock(db->torrent_list_mutex);
        for (unsigned int pos = 0; pos < info_hashes.length(); pos += 20) {
            std::string info_hash = info_hashes.substr(pos, 20);
            auto torrent_it = torrents_list.find(info_hash);
            if (torrent_it != torrents_list.end()) {
                torrent_it->second.free_torrent = fl;
                logger->info("updated torrent {} to FL {}", torrent_it->second.id, (int)fl);
            } else {
                logger->warn("failed to find torrent {} to FL {}", info_hash, (int)fl);
            }
        }
    } else if (action == "add_token") {
        std::string info_hash = hex_decode(params["info_hash"]);
        int userid = atoi(params["userid"].c_str());
        std::lock_guard<std::mutex> tl_lock(db->torrent_list_mutex);
        auto torrent_it = torrents_list.find(info_hash);
        if (torrent_it != torrents_list.end()) {
            torrent_it->second.tokened_users.insert(userid);
        } else {
            logger->warn("failed to find torrent to add a token for user {}", userid);
        }
    } else if (action == "remove_token") {
        std::string info_hash = hex_decode(params["info_hash"]);
        int userid = atoi(params["userid"].c_str());
        std::lock_guard<std::mutex> tl_lock(db->torrent_list_mutex);
        auto torrent_it = torrents_list.find(info_hash);
        if (torrent_it != torrents_list.end()) {
            torrent_it->second.tokened_users.erase(userid);
        } else {
            logger->warn(
                "failed to find torrent {} to remove token for user ",
                info_hash, userid
            );
        }
    } else if (action == "delete_torrent") {
        std::string info_hash = params["info_hash"];
        info_hash = hex_decode(info_hash);
        int reason = -1;
        auto reason_it = params.find("reason");
        if (reason_it != params.end()) {
            reason = atoi(params["reason"].c_str());
        }
        std::lock_guard<std::mutex> tl_lock(db->torrent_list_mutex);
        auto torrent_it = torrents_list.find(info_hash);
        if (torrent_it != torrents_list.end()) {
            logger->info(
                "deleted torrent {} for the reason '{}'",
                torrent_it->second.id, get_del_reason(reason)
            );
            stats.leechers -= torrent_it->second.leechers.size();
            stats.seeders -= torrent_it->second.seeders.size();
            for (auto &p : torrent_it->second.leechers) {
                p.second.user->decr_leeching();
            }
            for (auto &p : torrent_it->second.seeders) {
                p.second.user->decr_seeding();
            }
            std::lock_guard<std::mutex> dr_lock(del_reasons_lock);
            del_message msg;
            msg.reason = reason;
            msg.time = time(NULL);
            del_reasons[info_hash] = msg;
            torrents_list.erase(torrent_it);
        } else {
            logger->warn("failed to find torrent {} to delete", bintohex(info_hash));
        }
    } else if (action == "add_user") {
        std::string passkey = params["passkey"];
        userid_t userid = strtoint32(params["id"]);
        std::lock_guard<std::mutex> ul_lock(db->user_list_mutex);
        auto u = users_list.find(passkey);
        if (u == users_list.end()) {
            bool protect_ip = params["visible"] == "0";
            user_ptr tmp_user = std::make_shared<user>(userid, true, protect_ip);
            users_list.insert(std::pair<std::string, user_ptr>(passkey, tmp_user));
            logger->info("added user {} with id {}", passkey, userid);
        } else {
            logger->warn(
                "tried to add already known user {} with id {}",
                passkey, userid
            );
            u->second->set_deleted(false);
        }
    } else if (action == "remove_user") {
        std::string passkey = params["passkey"];
        std::lock_guard<std::mutex> ul_lock(db->user_list_mutex);
        auto u = users_list.find(passkey);
        if (u != users_list.end()) {
            logger->info("removed user {} with id {}",
                passkey,
                u->second->get_id()
            );
            u->second->set_deleted(true);
            users_list.erase(u);
        }
    } else if (action == "remove_users") {
        // Each passkey is exactly 32 characters long.
        std::string passkeys = params["passkeys"];
        std::lock_guard<std::mutex> ul_lock(db->user_list_mutex);
        for (unsigned int pos = 0; pos < passkeys.length(); pos += 32) {
            std::string passkey = passkeys.substr(pos, 32);
            auto u = users_list.find(passkey);
            if (u != users_list.end()) {
                logger->info(
                    "removed user {} with id {}",
                    passkey, u->second->get_id()
                );
                u->second->set_deleted(true);
                users_list.erase(passkey);
            }
        }
    } else if (action == "update_user") {
        std::string passkey = params["passkey"];
        bool can_leech = true;
        bool protect_ip = false;
        if (params["can_leech"] == "0") {
            can_leech = false;
        }
        if (params["visible"] == "0") {
            protect_ip = true;
        }
        std::lock_guard<std::mutex> ul_lock(db->user_list_mutex);
        user_list::iterator i = users_list.find(passkey);
        if (i == users_list.end()) {
            logger->warn(
                "no user with passkey {} found when attempting to change leeching status!",
                passkey
            );
        } else {
            i->second->set_protected(protect_ip);
            i->second->set_leechstatus(can_leech);
            logger->info(
                "updated user {} protect({}) leech({})",
                passkey, protect_ip, can_leech
            );
        }
    } else if (action == "add_whitelist") {
        std::string peer_id = params["peer_id"];
        std::lock_guard<std::mutex> wl_lock(db->whitelist_mutex);
        whitelist.push_back(peer_id);
        logger->info("whitelisted {}", peer_id);
    } else if (action == "remove_whitelist") {
        std::string peer_id = params["peer_id"];
        std::lock_guard<std::mutex> wl_lock(db->whitelist_mutex);
        for (unsigned int i = 0; i < whitelist.size(); i++) {
            if (whitelist[i].compare(peer_id) == 0) {
                whitelist.erase(whitelist.begin() + i);
                logger->info("dewhitelisted {}", peer_id);
                break;
            }
        }
    } else if (action == "edit_whitelist") {
        std::string new_peer_id = params["new_peer_id"];
        std::string old_peer_id = params["old_peer_id"];
        std::lock_guard<std::mutex> wl_lock(db->whitelist_mutex);
        for (unsigned int i = 0; i < whitelist.size(); i++) {
            if (whitelist[i].compare(old_peer_id) == 0) {
                whitelist.erase(whitelist.begin() + i);
                break;
            }
        }
        whitelist.push_back(new_peer_id);
        logger->info("whitelist edited from {} to {}", old_peer_id, new_peer_id);
    } else if (action == "update_announce_interval") {
        const std::string interval = params["new_announce_interval"];
        conf->set("announce_interval", interval);
        announce_interval = conf->get_uint("announce_interval");
        logger->info("edited announce interval to {}", announce_interval);
    } else if (action == "update_announce_jitter") {
        const std::string new_jitter = params["new_announce_jitter"];
        conf->set("announce_jitter", new_jitter);
        jitter = std::uniform_int_distribution<int>(0, conf->get_uint("announce_jitter"));
        logger->info("edited announce jitter to {}" , conf->get_uint("announce_jitter"));
    } else if (action == "info_torrent") {
        std::stringstream output;
        std::string info_hash_hex = params["info_hash"];
        std::string info_hash = hex_decode(info_hash_hex);
        std::lock_guard<std::mutex> tl_lock(db->torrent_list_mutex);
        auto torrent_it = torrents_list.find(info_hash);
        output << "{\"hash\":" << std::string(info_hash_hex);
        if (torrent_it != torrents_list.end()) {
            output << ",\"id\":" << std::to_string(torrent_it->second.id)
                << ",\"free\":" << std::to_string(torrent_it->second.free_torrent);
        } else {
            output << ",\"fail\":1";
        }
        output << "}\n";
        return http_response(output.str(), client_opts);
    }
    return http_response("success", client_opts);
}

/*
peer_list::iterator worker::add_peer(peer_list &peer_list, const peerkey_t &peer_key) {
    peer new_peer;
    auto it = peer_list.insert(std::pair<peerkey_t, peer>(peer_key, new_peer));
    return it.first;
}
*/

peer_list::iterator worker::add_leecher(torrent &tor, user_ptr &u, const addr_port &ap, const peerkey_t &peer_key) {
    auto insert = tor.leechers.insert({peer_key, peer(u, ap)});
    stats.leechers++;
    u->incr_leeching();
    return insert.first;
}

peer_list::iterator worker::add_seeder(torrent &tor, user_ptr &u, const addr_port &ap, const peerkey_t &peer_key) {
    auto insert = tor.seeders.insert({peer_key, peer(u, ap)});
    stats.seeders++;
    u->incr_seeding();
    return insert.first;
}

peer_list::iterator worker::move_seeder_to_leecher(torrent &tor, user_ptr &u, peer_list::iterator &peer_it, const peerkey_t &peer_key) {
    auto insert = tor.leechers.insert({peer_key, peer_it->second});
    tor.seeders.erase(peer_it);
    stats.leechers++;
    stats.seeders--;
    u->incr_leeching();
    u->decr_seeding();
    return insert.first;
}

peer_list::iterator worker::move_leecher_to_seeder(torrent &tor, user_ptr &u, peer_list::iterator &peer_it, const peerkey_t &peer_key) {
    auto insert = tor.seeders.insert({peer_key, peer_it->second});
    tor.leechers.erase(peer_it);
    stats.leechers--;
    stats.seeders++;
    u->decr_leeching();
    u->incr_seeding();
    return insert.first;
}

peer* worker::insert_seeder(torrent &tor, user_ptr &u, peer_list::iterator &peer_it, const peerkey_t &peer_key) {
    auto insert = tor.seeders.insert({peer_key, peer_it->second});
    tor.leechers.erase(peer_it);
    peer_it = insert.first;
    stats.leechers--;
    u->decr_leeching();
    // Only increment seeders if we actually inserted (not if key already existed)
    if (insert.second) {
        stats.seeders++;
        u->incr_seeding();
    }
    return &peer_it->second;
}

void worker::remove_seeder(torrent &tor, user_ptr &u, peer_list::iterator &peer_it) {
    tor.seeders.erase(peer_it);
    stats.seeders--;
    u->decr_seeding();
}

void worker::start_reaper() {
    if (!reaper_active) {
        std::thread thread(&worker::do_start_reaper, this);
        thread.detach();
    }
}

void worker::do_start_reaper() {
    reaper_active = true;
    reap_peers();
    reap_del_reasons();
    reaper_active = false;
}

void worker::reap_peers() {
    time_t max_time = time(NULL) - peers_timeout;
    logger->info("starting peer reaper, max time {}, timeout {}", max_time, peers_timeout);

    uint32_t reaped_leecher   = 0;
    uint32_t reaped_seeder    = 0;
    uint32_t cleared_torrents = 0;
    uint32_t total_torrent    = 0;
    uint32_t total_seeder     = 0;
    uint32_t total_leecher    = 0;

    std::chrono::steady_clock::time_point lock_begin;
    std::chrono::steady_clock::time_point lock_end;
    std::chrono::steady_clock::time_point reap_end;
    {
        // Hold the lock for the entire reap operation to prevent iterator
        // invalidation from concurrent announce() calls modifying the peer lists.
        lock_begin = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> tl_lock(db->torrent_list_mutex);
        lock_end = std::chrono::steady_clock::now();

        for (auto t = torrents_list.begin(); t != torrents_list.end(); ++t) {
            total_torrent++;
            bool reaped_this = false;  // True if at least one peer was deleted from the current torrent
            auto p = t->second.leechers.begin();
            while (p != t->second.leechers.end()) {
                total_leecher++;
                if (p->second.last_announced > max_time) {
                    p++;
                } else {
                    p->second.user->decr_leeching();
                    p = t->second.leechers.erase(p);
                    reaped_this = true;
                    reaped_leecher++;
                }
            }
            p = t->second.seeders.begin();
            while (p != t->second.seeders.end()) {
                total_seeder++;
                if (p->second.last_announced > max_time) {
                    p++;
                } else {
                    p->second.user->decr_seeding();
                    p = t->second.seeders.erase(p);
                    reaped_this = true;
                    reaped_seeder++;
                }
            }
            if (reaped_this && t->second.seeders.empty() && t->second.leechers.empty()) {
                db->record_torrent(
                    t->second.id, 0, 0, 0, t->second.balance
                );
                cleared_torrents++;
            }
        }
        reap_end = std::chrono::steady_clock::now();
    }

    auto lock_duration = std::chrono::duration_cast<std::chrono::microseconds>(lock_end - lock_begin);
    auto reap_duration = std::chrono::duration_cast<std::chrono::microseconds>(reap_end - lock_end);

    stats.reap_total++;

    uint32_t old_leech = stats.leechers;
    uint32_t old_seed  = stats.seeders;
    stats.leechers     = total_leecher;
    stats.seeders      = total_seeder;
    stats.reap_lock_duration.fetch_add(
        lock_duration.count()
    );
    stats.reap_duration.fetch_add(
        reap_duration.count()
    );

    logger->info(
        "reaped {} leechers and {} seeders in {}us,"
        " lock acquired in {}us, torrents scanned: {}, reset {}"
        " (adjusted seeders: {} => {}, leechers: {} => {})",
        reaped_leecher, reaped_seeder, reap_duration.count(),
        lock_duration.count(), total_torrent, cleared_torrents,
        old_seed, total_seeder, old_leech, total_leecher
    );
}

void worker::reap_del_reasons() {
    time_t max_time = time(NULL) - del_reason_lifetime;
    logger->info("starting deleted reason reaper, max time {}, timeout {}", max_time, del_reason_lifetime);
    unsigned int reaped = 0;

    // Hold the lock for the entire operation to prevent iterator invalidation
    {
        std::lock_guard<std::mutex> dr_lock(del_reasons_lock);
        for (auto it = del_reasons.begin(); it != del_reasons.end(); ) {
            if (it->second.time > max_time) {
                it++;
            } else {
                it = del_reasons.erase(it);
                reaped++;
            }
        }
    }
    logger->info("reaped {} torrent deleted reasons", reaped);
}

std::string worker::get_del_reason(int code) {
    switch (code) {
        case DUPE:
            return "Dupe";
            break;
        case TRUMP:
            return "Trump";
            break;
        case BAD_FILE_NAMES:
            return "Bad File Names";
            break;
        case BAD_FOLDER_NAMES:
            return "Bad Folder Names";
            break;
        case BAD_TAGS:
            return "Bad Tags";
            break;
        case BAD_FORMAT:
            return "Disallowed Format";
            break;
        case DISCS_MISSING:
            return "Discs Missing";
            break;
        case DISCOGRAPHY:
            return "Discography";
            break;
        case EDITED_LOG:
            return "Edited Log";
            break;
        case INACCURATE_BITRATE:
            return "Inaccurate Bitrate";
            break;
        case LOW_BITRATE:
            return "Low Bitrate";
            break;
        case MUTT_RIP:
            return "Mutt Rip";
            break;
        case BAD_SOURCE:
            return "Disallowed Source";
            break;
        case ENCODE_ERRORS:
            return "Encode Errors";
            break;
        case BANNED:
            return "Specifically Banned";
            break;
        case TRACKS_MISSING:
            return "Tracks Missing";
            break;
        case TRANSCODE:
            return "Transcode";
            break;
        case CASSETTE:
            return "Unapproved Cassette";
            break;
        case UNSPLIT_ALBUM:
            return "Unsplit Album";
            break;
        case USER_COMPILATION:
            return "User Compilation";
            break;
        case WRONG_FORMAT:
            return "Wrong Format";
            break;
        case WRONG_MEDIA:
            return "Wrong Media";
            break;
        case AUDIENCE:
            return "Audience Recording";
            break;
        default:
            return "";
            break;
    }
}
