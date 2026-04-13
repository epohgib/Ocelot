// Copyright [2017-2026] Orpheus

#include <spdlog/spdlog.h>
#include <fmt/format.h>
#include <unistd.h>

#include <chrono>
#include <ctime>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>

#include "ocelot.h"
#include "db.h"
#include "misc_functions.h"
#include "config.h"

mysql::mysql(config * conf) :
    u_active(false),
    t_active(false),
    p_active(false),
    s_active(false),
    tok_active(false),
    logger(spdlog::get("logger")
) {
    load_config(conf);
    if (mysql_db.empty()) {
        logger->critical("No database configured");
        return;
    }

    try {
        mysqlpp::ReconnectOption reconnect(true);
        conn.set_option(&reconnect);
        conn.connect(mysql_db.c_str(), mysql_host.c_str(), mysql_username.c_str(), mysql_password.c_str(), mysql_port);
    } catch (const mysqlpp::Exception &er) {
        logger->critical("Failed to connect to MySQL: {}", er.what());
        return;
    }

    // these are destined to grow very large
    heavy_peer_buffer.reserve(520000);
    light_peer_buffer.reserve(520000);
    snatch_buffer.reserve(65500);
    token_buffer.reserve(65500);
    torrent_buffer.reserve(65500);
    user_buffer.reserve(65500);

    if (!readonly) {
        logger->info("Clearing xbt_files_users and resetting peer counts...");
        logger->flush();
        clear_peer_data();
        logger->info("done");
    }
}

void mysql::load_config(config * conf) {
    mysql_db       = conf->get_str("mysql_db");
    mysql_host     = conf->get_str("mysql_host");
    mysql_username = conf->get_str("mysql_username");
    mysql_password = conf->get_str("mysql_password");
    mysql_port     = conf->get_uint("mysql_port");
    readonly       = conf->get_bool("readonly");
}

void mysql::reload_config(config * conf) {
    load_config(conf);
}

bool mysql::connected() {
    return conn.connected();
}

mysqlpp::Connection mysql::create_connection() {
    mysqlpp::Connection c(conn);
    c.set_option(new mysqlpp::ReconnectOption(true));
    return c;
}

void mysql::clear_peer_data() {
    try {
        mysqlpp::Query query = conn.query("TRUNCATE xbt_files_users;");
        if (!query.exec()) {
            logger->error("Unable to truncate xbt_files_users!");
        }
        query = conn.query("UPDATE torrents_leech_stats SET Seeders = 0, Leechers = 0;");
        if (!query.exec()) {
            logger->error("Unable to reset seeder and leecher count!");
        }
    } catch (const mysqlpp::BadQuery &er) {
        logger->error("bad query in clear_peer_data: {}", er.what());
    } catch (const mysqlpp::Exception &er) {
        logger->error("query execption in clear_peer_data: {}", er.what());
    }
}

void mysql::load_torrents(torrent_list &torrents) {
    mysqlpp::Query query = conn.query(
        "SELECT t.ID, t.info_hash, t.freetorrent, tls.Snatched FROM torrents t INNER JOIN torrents_leech_stats tls ON (tls.TorrentID = t.ID)"
    );
    try {
        mysqlpp::StoreQueryResult res = query.store();
        std::unordered_set<std::string> cur_keys;
        size_t num_rows = res.num_rows();
        std::lock_guard<std::mutex> tl_lock(torrent_list_mutex);
        if (torrents.size() == 0) {
            torrents.reserve(num_rows * 1.05);  // Reserve 5% extra space to prevent rehashing
        } else {
            // Create set with all currently known info hashes to remove nonexistent ones later
            cur_keys.reserve(torrents.size());
            for (auto const &it : torrents) {
                cur_keys.insert(it.first);
            }
        }
        for (size_t i = 0; i < num_rows; i++) {
            std::string info_hash;
            res[i][1].to_string(info_hash);
            if (info_hash.empty()) {
                continue;
            }
            mysqlpp::sql_enum free_torrent(res[i][2]);

            torrent tmp_tor;
            auto it = torrents.insert(std::pair<std::string, torrent>(info_hash, tmp_tor));
            torrent &tor = (it.first)->second;
            if (it.second) {
                tor.id                   = res[i][0];
                tor.completed            = res[i][3];
                tor.balance              = 0;
                tor.last_flushed         = 0;
                tor.last_selected_seeder = 0;
            } else {
                tor.tokened_users.clear();
                cur_keys.erase(info_hash);
            }
            if (free_torrent == "1") {
                tor.free_torrent = FREE;
            } else if (free_torrent == "2") {
                tor.free_torrent = NEUTRAL;
            } else {
                tor.free_torrent = NORMAL;
            }
        }
        for (auto const &info_hash : cur_keys) {
            // Remove tracked torrents that weren't found in the database
            auto it = torrents.find(info_hash);
            if (it != torrents.end()) {
                torrent &tor = it->second;
                stats.leechers -= tor.leechers.size();
                stats.seeders -= tor.seeders.size();
                for (auto &p : tor.leechers) {
                    p.second.user->decr_leeching();
                }
                for (auto &p : tor.seeders) {
                    p.second.user->decr_seeding();
                }
                torrents.erase(it);
            }
        }
    } catch (const mysqlpp::BadQuery &er) {
        logger->error("Query error in load_torrents: {}", er.what());
        return;
    }
    logger->info("Loaded {} torrents", torrents.size());
    load_tokens(torrents);
}

void mysql::load_users(user_list &users) {
    mysqlpp::Query query = conn.query(
        "SELECT ID, can_leech, torrent_pass, (Visible='0' OR IP='127.0.0.1') AS Protected FROM users_main WHERE Enabled='1'"
    );
    try {
        mysqlpp::StoreQueryResult res = query.store();
        size_t num_rows = res.num_rows();
        std::unordered_set<std::string> cur_keys;
        std::lock_guard<std::mutex> ul_lock(user_list_mutex);
        if (users.size() == 0) {
            users.reserve(static_cast<unsigned long>(num_rows * 1.05));  // Reserve 5% extra space to prevent rehashing
        } else {
            // Create set with all currently known user keys to remove nonexistent ones later
            cur_keys.reserve(users.size());
            for (auto const &it : users) {
                cur_keys.insert(it.first);
            }
        }
        for (size_t i = 0; i < num_rows; i++) {
            std::string passkey(res[i][2]);
            bool protect_ip = res[i][3];
            user_ptr tmp_user = std::make_shared<user>(res[i][0], res[i][1], protect_ip);
            auto it = users.insert(std::pair<std::string, user_ptr>(passkey, tmp_user));
            if (!it.second) {
                user_ptr &u = (it.first)->second;
                u->set_leechstatus(res[i][1]);
                u->set_protected(protect_ip);
                u->set_deleted(false);
                cur_keys.erase(passkey);
            }
        }
        for (auto const &passkey : cur_keys) {
            // Remove users that weren't found in the database
            auto it = users.find(passkey);
            if (it != users.end()) {
                it->second->set_deleted(true);
                users.erase(it);
            }
        }
    } catch (const mysqlpp::BadQuery &er) {
        logger->error("bad query in load_users: {}", er.what());
        return;
    }
    logger->info("Loaded {} users", users.size());
}

void mysql::load_tokens(torrent_list &torrents) {
    mysqlpp::Query query = conn.query("SELECT uf.UserID, t.info_hash FROM users_freeleeches AS uf INNER JOIN torrents AS t ON t.ID = uf.TorrentID WHERE uf.Expired = '0';");
    int token_count = 0;
    try {
        mysqlpp::StoreQueryResult res = query.store();
        size_t num_rows = res.num_rows();
        std::lock_guard<std::mutex> tl_lock(torrent_list_mutex);
        for (size_t i = 0; i < num_rows; i++) {
            std::string info_hash;
            res[i][1].to_string(info_hash);
            auto it = torrents.find(info_hash);
            if (it != torrents.end()) {
                torrent &tor = it->second;
                tor.tokened_users.insert(res[i][0]);
                ++token_count;
            }
        }
    } catch (const mysqlpp::BadQuery &er) {
        logger->error("Query error in load_tokens: {}", er.what());
        return;
    }
    logger->info("Loaded {} tokens", token_count);
}


void mysql::load_whitelist(std::vector<std::string> &whitelist) {
    mysqlpp::Query query = conn.query("SELECT peer_id FROM xbt_client_whitelist");
    try {
        mysqlpp::StoreQueryResult res = query.store();
        size_t num_rows = res.num_rows();
        std::lock_guard<std::mutex> wl_lock(whitelist_mutex);
        whitelist.clear();
        for (size_t i = 0; i<num_rows; i++) {
            std::string peer_id;
            res[i][0].to_string(peer_id);
            whitelist.push_back(peer_id);
        }
    } catch (const mysqlpp::BadQuery &er) {
        logger->error("Query error in load_whitelist: {}", er.what());
        return;
    }
    if (whitelist.size() == 0) {
        logger->info("Assuming no whitelist desired, disabling");
    } else {
        logger->info("Loaded {} clients into the whitelist", whitelist.size());
    }
}

std::string mysql::escape(const std::string &value) {
    // this sucks, but the mysqlpp interface is utterly idiotic
    mysqlpp::Query q = conn.query();
    q << mysqlpp::quote << value;
    return q.str();
}

void mysql::record_peer(
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
) {
    std::lock_guard<std::mutex> lock(peer_buffer_lock);
    fmt::format_to(
        std::back_inserter(heavy_peer_buffer),
        "({},{},{},"
        "{},{},{},{},{},{},"
        "{},{},{},"
        "{},{},{}),",
        user_id, torrent_id, active ? 1 : 0,
        uploaded, downloaded, upspeed, downspeed, left, corrupt,
        seed_time, announces, addr,
        escape(peer_id), escape(useragent), time(NULL)
    );
}

void mysql::record_peer(
    const userid_t user_id,
    const torid_t torrent_id,
    const uint32_t seed_time,
    const uint32_t announces,
    const std::string &peer_id
) {
    std::lock_guard<std::mutex> lock(peer_buffer_lock);
    fmt::format_to(
        std::back_inserter(light_peer_buffer),
        "({},{},{},{},{},{}),",
        user_id, torrent_id, announces, seed_time, escape(peer_id), time(NULL)
    );
}

void mysql::record_snatch(
    const userid_t user_id,
    const torid_t torrent_id,
    const std::string &addr
) {
    std::lock_guard<std::mutex> lock(snatch_buffer_lock);
    fmt::format_to(
        std::back_inserter(snatch_buffer),
        "({},{},{},{}),",
        user_id, torrent_id, time(NULL), addr
    );
}

void mysql::record_token(
    const userid_t user_id,
    const torid_t torrent_id,
    const int64_t downloaded_change
) {
    std::lock_guard<std::mutex> lock(token_buffer_lock);
    fmt::format_to(
        std::back_inserter(token_buffer),
        "({},{},{}),",
        user_id, torrent_id, downloaded_change
    );
}

void mysql::record_torrent(
    const torid_t torrent_id,
    const uint32_t seeder_total,
    const uint32_t leecher_total,
    const bool completed,
    const int64_t balance
) {
    std::lock_guard<std::mutex> lock(torrent_buffer_lock);
    fmt::format_to(
        std::back_inserter(torrent_buffer),
        "({},{},{},{},{}),",
        torrent_id, seeder_total, leecher_total, completed ? 1 : 0, balance
    );
}

void mysql::record_user(
    const userid_t userid,
    const int64_t uploaded_change,
    const int64_t downloaded_change
) {
    fmt::format_to(
        std::back_inserter(user_buffer),
        "({},{},{}),",
        userid, uploaded_change, downloaded_change
    );
}

bool mysql::all_clear() const {
    return (
        user_queue.size()       == 0
        && torrent_queue.size() == 0
        && peer_queue.size()    == 0
        && snatch_queue.size()  == 0
        && token_queue.size()   == 0
    );
}

void mysql::flush() {
    flush_users();
    flush_torrents();
    flush_snatches();
    flush_peers();
    flush_tokens();
}

void mysql::flush_users() {
    std::lock_guard<std::mutex> ub_lock(user_buffer_lock);
    if (readonly) {
        user_buffer = "";
        return;
    }
    std::lock_guard<std::mutex> uq_lock(user_queue_lock);
    size_t qsize = user_queue.size();
    if (verbose_flush || qsize > 0) {
        logger->info(
            "flush_users() chunks: {}, first chunk len: {}",
            qsize, user_queue.front().size()
        );
    }
    if (user_buffer.empty()) {
        return;
    }
    user_buffer.pop_back(); // remove trailing comma
    user_queue.push(
        fmt::format(
            "INSERT INTO users_leech_stats (UserID,Uploaded,Downloaded)"
            "VALUES{}"
            "ON DUPLICATE KEY UPDATE Uploaded=Uploaded+VALUES(Uploaded),Downloaded=Downloaded+VALUES(Downloaded)",
            user_buffer
        )
    );
    user_buffer = "";
    stats.user_queue_size = qsize + 1;
    if (!u_active) {
        std::thread thread(&mysql::do_flush_users, this);
        thread.detach();
    }
}

void mysql::flush_torrents() {
    std::lock_guard<std::mutex> tb_lock(torrent_buffer_lock);
    if (readonly) {
        torrent_buffer = "";
        return;
    }
    std::lock_guard<std::mutex> tq_lock(torrent_queue_lock);
    size_t qsize = torrent_queue.size();
    if (verbose_flush || qsize > 0) {
        logger->info(
            "flush_torrents() chunks: {}, first chunk len: {}",
            qsize, torrent_queue.front().size()
        );
    }
    if (torrent_buffer.empty()) {
        return;
    }
    torrent_buffer.pop_back();
    torrent_queue.push(
        fmt::format(
            "INSERT INTO torrents_leech_stats(TorrentID,Seeders,Leechers,Snatched,Balance)"
            "VALUES{}"
            "ON DUPLICATE KEY UPDATE Seeders=VALUES(Seeders),Leechers=VALUES(Leechers),"
            "Snatched=Snatched+VALUES(Snatched),Balance=VALUES(Balance),last_action="
            "IF(VALUES(Seeders)>0,NOW(),last_action)",
            torrent_buffer
        )
    );
    stats.torrent_queue_size = qsize + 1;
    torrent_buffer = "";
    if (!t_active) {
        std::thread thread(&mysql::do_flush_torrents, this);
        thread.detach();
    }
}

void mysql::flush_snatches() {
    std::lock_guard<std::mutex> sb_lock(snatch_buffer_lock);
    if (readonly) {
        snatch_buffer = "";
        return;
    }
    std::lock_guard<std::mutex> sq_lock(snatch_queue_lock);
    size_t qsize = snatch_queue.size();
    if (verbose_flush || qsize > 0) {
        logger->info(
            "flush_snatches() chunks: {}, first chunk len={}",
            qsize, snatch_queue.front().size()
        );
    }
    if (snatch_buffer.empty()) {
        return;
    }
    snatch_buffer.pop_back();
    snatch_queue.push(
        fmt::format(
            "INSERT IGNORE INTO xbt_snatched(uid,fid,tstamp,IP)VALUES{}",
            snatch_buffer
        )
    );
    snatch_buffer = "";
    stats.snatch_queue_size = qsize + 1;
    if (!s_active) {
        std::thread thread(&mysql::do_flush_snatches, this);
        thread.detach();
    }
}

void mysql::flush_peers() {
    std::lock_guard<std::mutex> pb_lock(peer_buffer_lock);
    if (readonly) {
        light_peer_buffer = "";
        heavy_peer_buffer = "";
        return;
    }
    std::lock_guard<std::mutex> pq_lock(peer_queue_lock);
    size_t qsize = peer_queue.size();
    short qsize_added = 0;
    if (verbose_flush || qsize > 0) {
        logger->info(
            "flush_peers() chunks: {}, first chunk length: {}",
            qsize, peer_queue.front().size()
        );
    }

    // Nothing to do
    if (light_peer_buffer.empty() && heavy_peer_buffer.empty()) {
        return;
    }

    if (!heavy_peer_buffer.empty()) {
        // Because xfu inserts are slow and ram is not infinite we need to
        // limit this queue's size
        // xfu will be messed up if the light query inserts a new row,
        // but that's better than an oom crash
        if (qsize >= 3000) {
            peer_queue.pop();
        } else {
            qsize_added += 1;
        }
        heavy_peer_buffer.pop_back();
        peer_queue.push(
            fmt::format(
                "INSERT INTO xbt_files_users(uid,fid,active,uploaded,downloaded,upspeed,downspeed,remaining,corrupt,timespent,announced,ip,peer_id,useragent,mtime)VALUES"
                "{}"
                "ON DUPLICATE KEY UPDATE active=VALUES(active),uploaded=VALUES(uploaded),"
                "downloaded=VALUES(downloaded),upspeed=VALUES(upspeed),"
                "downspeed=VALUES(downspeed),remaining=VALUES(remaining),"
                "corrupt=VALUES(corrupt),timespent=VALUES(timespent),"
                "announced=VALUES(announced),mtime=VALUES(mtime)",
                heavy_peer_buffer
            )
        );
        heavy_peer_buffer = "";
    }
    if (!light_peer_buffer.empty()) {
        // See comment above
        if (qsize >= 3000) {
            peer_queue.pop();
        } else {
            qsize_added += 1;
        }
        light_peer_buffer.pop_back();
        peer_queue.push(
            fmt::format(
                "INSERT INTO xbt_files_users(uid,fid,timespent,announced,peer_id,mtime)"
                "VALUES{}"
                "ON DUPLICATE KEY UPDATE upspeed=0,downspeed=0,timespent=VALUES(timespent),"
                "announced=VALUES(announced),mtime=VALUES(mtime)",
                light_peer_buffer
            )
        );
        light_peer_buffer = "";
    }
    stats.peer_queue_size = qsize + qsize_added;

    if (!p_active) {
        std::thread thread(&mysql::do_flush_peers, this);
        thread.detach();
    }
}

void mysql::flush_tokens() {
    if (readonly) {
        token_buffer = "";
        return;
    }
    std::lock_guard<std::mutex> tq_lock(token_queue_lock);
    size_t qsize = token_queue.size();
    if (verbose_flush || qsize > 0) {
        logger->info(
            "flush_tokens() chunks: {}, first chunk length: {}",
            qsize, token_queue.front().size()
        );

    }
    if (token_buffer.empty()) {
        return;
    }
    token_buffer.pop_back();
    token_queue.push(
        fmt::format(
            "INSERT INTO users_freeleeches(UserID,TorrentID,Downloaded)"
            "VALUES{}"
            "ON DUPLICATE KEY UPDATE Downloaded=Downloaded+VALUES(Downloaded)",
            token_buffer
        )
    );
    token_buffer = "";
    stats.token_queue_size = qsize + 1;
    if (!tok_active) {
        std::thread thread(&mysql::do_flush_tokens, this);
        thread.detach();
    }
}

void mysql::do_flush_users() {
    u_active = true;
    try {
        mysqlpp::Connection c = create_connection();
        std::string sql;
        while (user_queue.size() > 0) {
            try {
                sql = user_queue.front();
                mysqlpp::Query query = c.query(sql);
                if (!query.exec()) {
                    logger->info("User flush failed ({} remain)", user_queue.size());
                    std::this_thread::sleep_for(std::chrono::seconds(3));
                    break;
                } else {
                    std::lock_guard<std::mutex> uq_lock(user_queue_lock);
                    user_queue.pop();
                    stats.user_queue_size -= 1;
                }
            }
            catch (const mysqlpp::BadQuery &er) {
                sql.resize(800);
                logger->error(
                    "bad query: {} in do_flush_users, qlength: {}, chunks: {} sql={} --EOQ",
                    er.what(),
                    user_queue.front().size(),
                    user_queue.size(),
                    sql
                );
                std::this_thread::sleep_for(std::chrono::seconds(3));
                break;
            } catch (const mysqlpp::Exception &er) {
                sql.resize(800);
                logger->error(
                    "query exception: {} in do_flush_users, qlength: {}, chunks: {}",
                    er.what(),
                    user_queue.front().size(),
                    user_queue.size()
                );
                std::this_thread::sleep_for(std::chrono::seconds(3));
                break;
            }
        }
    }
    catch (const mysqlpp::Exception &er) {
        logger->error("MySQL error in do_flush_users: {}", er.what());
    }
    u_active = false;
}

void mysql::do_flush_torrents() {
    t_active = true;
    try {
        mysqlpp::Connection c = create_connection();
        std::string sql;
        while (torrent_queue.size() > 0) {
            try {
                sql = torrent_queue.front();
                if (sql.empty()) {
                    torrent_queue.pop();
                    stats.torrent_queue_size -= 1;
                    continue;
                }
                mysqlpp::Query query = c.query(sql);
                if (!query.exec()) {
                    logger->info("do_flush_torrents failed ({} remain)", torrent_queue.size());
                    std::this_thread::sleep_for(std::chrono::seconds(3));
                    break;
                } else {
                    std::lock_guard<std::mutex> tq_lock(torrent_queue_lock);
                    torrent_queue.pop();
                    stats.torrent_queue_size -= 1;
                }
            }
            catch (const mysqlpp::BadQuery &er) {
                sql.resize(800);
                logger->error(
                    "bad query: {} in do_flush_torrents, qlength: {}, chunks: {} sql={} --EOQ",
                    er.what(),
                    torrent_queue.front().size(),
                    torrent_queue.size(),
                    sql
                );
                std::this_thread::sleep_for(std::chrono::seconds(3));
                break;
            } catch (const mysqlpp::Exception &er) {
                logger->error(
                    "query exception: {} in do_flush_torrents, qlength: {}, chunks: {}",
                    er.what(),
                    torrent_queue.front().size(),
                    torrent_queue.size()
                );
                std::this_thread::sleep_for(std::chrono::seconds(3));
                break;
            }
        }
    }
    catch (const mysqlpp::Exception &er) {
        logger->error("MySQL error in do_flush_torrents {}", er.what());
    }
    t_active = false;
}

void mysql::do_flush_peers() {
    p_active = true;
    try {
        mysqlpp::Connection c = create_connection();
        std::string sql;
        while (peer_queue.size() > 0) {
            try {
                sql = peer_queue.front();
                mysqlpp::Query query = c.query(sql);
                if (!query.exec()) {
                    logger->info("do_flush_peers failed ({} remain)", peer_queue.size());
                    std::this_thread::sleep_for(std::chrono::seconds(3));
                    break;
                } else {
                    std::lock_guard<std::mutex> pq_lock(peer_queue_lock);
                    peer_queue.pop();
                    stats.peer_queue_size -= 1;
                }
            }
            catch (const mysqlpp::BadQuery &er) {
                sql.resize(800);
                logger->error(
                    "bad query: {} in do_flush_peers, qlength: {}, chunks: {} sql={} --EOQ",
                    er.what(),
                    peer_queue.front().size(),
                    peer_queue.size(),
                    sql
                );
                std::this_thread::sleep_for(std::chrono::seconds(3));
                break;
            } catch (const mysqlpp::Exception &er) {
                logger->error(
                    "query exception: {} in do_flush_peers, qlength: {}, chunks: {}",
                    er.what(),
                    peer_queue.front().size(),
                    peer_queue.size()
                );
                std::this_thread::sleep_for(std::chrono::seconds(3));
                break;
            }
        }
    }
    catch (const mysqlpp::Exception &er) {
        logger->error("MySQL error in do_flush_peers: {}", er.what());
    }
    p_active = false;
}

void mysql::do_flush_snatches() {
    s_active = true;
    try {
        mysqlpp::Connection c = create_connection();
        std::string sql;
        while (snatch_queue.size() > 0) {
            try {
                sql = snatch_queue.front();
                mysqlpp::Query query = c.query(sql);
                if (!query.exec()) {
                    logger->info("do_flush_snatches failed ({} remain)", snatch_queue.size());
                    std::this_thread::sleep_for(std::chrono::seconds(3));
                    break;
                } else {
                    std::lock_guard<std::mutex> sq_lock(snatch_queue_lock);
                    snatch_queue.pop();
                    stats.snatch_queue_size -= 1;
                }
            }
            catch (const mysqlpp::BadQuery &er) {
                sql.resize(800);
                logger->error(
                    "bad query: {} in do_flush_snatches, qlength: {}, chunks: {} sql={} --EOQ",
                    er.what(),
                    snatch_queue.front().size(),
                    snatch_queue.size(),
                    sql
                );
                std::this_thread::sleep_for(std::chrono::seconds(3));
                break;
            } catch (const mysqlpp::Exception &er) {
                logger->error(
                    "query exception: {} in do_flush_snatches, qlength: {}, chunks: {}",
                    er.what(),
                    snatch_queue.front().size(),
                    snatch_queue.size()
                );
                std::this_thread::sleep_for(std::chrono::seconds(3));
                break;
            }
        }
    }
    catch (const mysqlpp::Exception &er) {
        logger->error("MySQL error in do_flush_snatches: {}", er.what());
    }
    s_active = false;
}

void mysql::do_flush_tokens() {
    tok_active = true;
    try {
        mysqlpp::Connection c = create_connection();
        std::string sql;
        while (token_queue.size() > 0) {
            try {
                sql = token_queue.front();
                mysqlpp::Query query = c.query(sql);
                if (!query.exec()) {
                    logger->info("do_flush_snatches failed ({} remain)", token_queue.size());
                    std::this_thread::sleep_for(std::chrono::seconds(3));
                    break;
                } else {
                    std::lock_guard<std::mutex> tq_lock(token_queue_lock);
                    token_queue.pop();
                    stats.token_queue_size -= 1;
                }
            }
            catch (const mysqlpp::BadQuery &er) {
                sql.resize(800);
                logger->error(
                    "bad query: {} in do_flush_tokens, qlength: {}, chunks: {} sql={} --EOQ",
                    er.what(),
                    token_queue.front().size(),
                    token_queue.size(),
                    sql
                );
                std::this_thread::sleep_for(std::chrono::seconds(3));
                break;
            } catch (const mysqlpp::Exception &er) {
                logger->error(
                    "query exception: {} in do_flush_tokens, qlength: {}, chunks: {}",
                    er.what(),
                    token_queue.front().size(),
                    token_queue.size()
                );
                std::this_thread::sleep_for(std::chrono::seconds(3));
                break;
            }
        }
    }
    catch (const mysqlpp::Exception &er) {
        logger->error("MySQL error in do_flush_tokens: {}", er.what());
    }
    tok_active = false;
}
