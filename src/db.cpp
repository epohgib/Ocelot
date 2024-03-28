// Copyright [2017-2024] Orpheus

#include <spdlog/spdlog.h>
#include <unistd.h>

#include <chrono>
#include <string>
#include <iostream>
#include <queue>
#include <ctime>
#include <mutex>
#include <thread>
#include <utility>
#include <unordered_set>

#include "ocelot.h"
#include "db.h"
#include "user.h"
#include "misc_functions.h"
#include "config.h"

#define DB_LOCK_TIMEOUT 50

mysql::mysql(config * conf) :
        update_heavy_peer_buffer(*this), update_light_peer_buffer(*this),
        update_snatch_buffer(*this), update_token_buffer(*this),
        update_torrent_buffer(*this), update_user_buffer(*this),
        peer_flush_active(false), snatch_flush_active(false), token_flush_active(false), torrent_flush_active(false), user_flush_active(false) {
    logger = spdlog::get("logger");
    load_config(conf);
    if (mysql_db.empty()) {
        logger->error("No database selected");
        return;
    }

    try {
        mysqlpp::ReconnectOption reconnect(true);
        conn.set_option(&reconnect);
        conn.connect(mysql_db.c_str(), mysql_host.c_str(), mysql_username.c_str(), mysql_password.c_str(), mysql_port);
    } catch (const mysqlpp::Exception &er) {
        logger->error("Failed to connect to MySQL ({})", er.what());
        return;
    }

    if (!readonly) {
        logger->info("Clearing xbt_files_users and resetting peer counts...");
        logger->flush();
        clear_peer_data();
        logger->info("done");
    }
}

void mysql::load_config(config * conf) {
    mysql_db = conf->get_str("mysql_db");
    mysql_host = conf->get_str("mysql_host");
    mysql_username = conf->get_str("mysql_username");
    mysql_password = conf->get_str("mysql_password");
    mysql_port = conf->get_uint("mysql_port");
    readonly = conf->get_bool("readonly");
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

std::string mysql::quote(std::string value) {
    mysqlpp::Query query = conn.query();
    query.escape_string(&value);
    return '\'' + value + '\'';
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
        logger->error("Query error in clear_peer_data: {}", er.what());
    } catch (const mysqlpp::Exception &er) {
        logger->error("Query error in clear_peer_data: {}", er.what());
    }
}

void mysql::load_torrents(torrent_list &torrents) {
    mysqlpp::Query query = conn.query("SELECT t.ID, t.info_hash, t.freetorrent, tls.Snatched FROM torrents t INNER JOIN torrents_leech_stats tls ON (tls.TorrentID = t.ID) ORDER BY t.ID");
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
                tor.id = res[i][0];
                tor.balance = 0;
                tor.completed = res[i][3];
                tor.last_selected_seeder = "";
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
    std::string sql(
        "SELECT ID, can_leech, torrent_pass, (Visible='0' OR IP='127.0.0.1') AS Protected"
        " FROM users_main WHERE Enabled='1'"
    );
    mysqlpp::Query query = conn.query(sql);
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
        logger->error("Query error in load_users: {} [{}]", er.what(), sql);
        return;
    }
    logger->info("Loaded {} users", users.size());
}

void mysql::load_tokens(torrent_list &torrents) {
    std::string sql(
        "SELECT uf.UserID, t.info_hash FROM users_freeleeches AS uf "
        "INNER JOIN torrents AS t ON t.ID = uf.TorrentID WHERE uf.Expired = '0'"
    );
    mysqlpp::Query query = conn.query(sql);
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
        logger->error("Query error in load_tokens: {} [{}]", er.what(), sql);
        return;
    }
    logger->info("Loaded {} tokens", token_count);
}


void mysql::load_whitelist(std::vector<std::string> &whitelist) {
    std::string sql("SELECT peer_id FROM xbt_client_whitelist");
    mysqlpp::Query query = conn.query(sql);
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
        logger->error("Query error in load_whitelist: {} [{}]", er.what(), sql);
        return;
    }
    logger->info("Loaded {} clients into the whitelist", whitelist.size());
}

void mysql::record_peer(const std::string &record) {
    std::lock_guard<std::mutex> buf_lock(peer_buffer_lock);
    update_heavy_peer_buffer += record;
}

void mysql::record_peer_light(const std::string &record) {
    std::lock_guard<std::mutex> buf_lock(peer_light_buffer_lock);
    update_light_peer_buffer += record;
}

void mysql::record_snatch(const std::string &record) {
    std::lock_guard<std::mutex> buf_lock(snatch_buffer_lock);
    update_snatch_buffer += record;
}

void mysql::record_token(const std::string &record) {
    std::lock_guard<std::mutex> buf_lock(token_buffer_lock);
    update_token_buffer += record;
}

void mysql::record_torrent(const std::string &record) {
    std::lock_guard<std::mutex> buf_lock(torrent_buffer_lock);
    update_torrent_buffer += record;
}

void mysql::record_user(const std::string &record) {
    std::lock_guard<std::mutex> buf_lock(user_buffer_lock);
    update_user_buffer += record;
}

bool mysql::all_clear() {
    return (user_queue.size() == 0 && torrent_queue.size() == 0 && peer_queue.size() == 0 && snatch_queue.size() == 0 && token_queue.size() == 0);
}

void mysql::flush() {
    flush_users();
    flush_torrents();
    flush_snatches();
    flush_peers();
    flush_tokens();
}

void mysql::flush_peers() {
    std::unique_lock<std::mutex> q_lock(peer_queue_lock);
    size_t qsize = peer_queue.size();
    if (verbose_flush || qsize > 0) {
        logger->info("Peer flush queue size: {}, next query length: {}", qsize, peer_queue.front().size());
    }
    q_lock.unlock();

    std::unique_lock<std::mutex> buf_lock(peer_buffer_lock);
    std::unique_lock<std::mutex> buf_light_lock(peer_light_buffer_lock);
    if (readonly) {
        update_light_peer_buffer.clear();
        update_heavy_peer_buffer.clear();
        return;
    }
    /* The first step to update the database is to transform the tuples that
     * have been stored into an SQL insert statement. The tuple buffer can then
     * be cleared and the statement saved in a queue. The next step is to see
     * if the queued statements can be sent to the database. If a database
     * flush is already active then nothing else happens.
     *
     * Otherwise, a new thread is spun off to take the queued statements and
     * execute them on the database in a FIFO manner. If for whatever reason
     * the database cannot process the statement (bad credentials,
     * incorrect/missing) the statements remain queued. If you are lucky, you
     * can make the necessary changes in the database (alter a table, create
     * the mysql user), and then the queue will empty.
     */
    if (update_light_peer_buffer.empty() && update_heavy_peer_buffer.empty() && qsize == 0) {
        // the buffers are empty and nothing is queued
        return;
    }

    int16_t qsize_added = 0;
    if (!update_heavy_peer_buffer.empty()) {
        // Because xfu inserts are slow and ram is not infinite we need to
        // limit this queue's size
        // xfu will be messed up if the light query inserts a new row,
        // but that's better than an oom crash
        if (qsize >= 1000) {
            std::lock_guard<std::mutex> q_lock(peer_queue_lock);
            peer_queue.pop();
            logger->error("Peer queue overflowed, update lost");
        } else {
            qsize_added += 1;
        }
        std::lock_guard<std::mutex> q_lock(peer_queue_lock);
        peer_queue.push(fmt::format(
            "INSERT INTO xbt_files_users"
            "(uid,fid,active,uploaded,downloaded,upspeed,downspeed,remaining"
            ",corrupt,timespent,announced,ip,peer_id,useragent,mtime)"
            "VALUES {} ON DUPLICATE KEY UPDATE active=VALUES(active)"
            ",uploaded=VALUES(uploaded),downloaded=VALUES(downloaded)"
            ",upspeed=VALUES(upspeed),downspeed=VALUES(downspeed)"
            ",remaining=VALUES(remaining),corrupt=VALUES(corrupt)"
            ",timespent=VALUES(timespent),announced=VALUES(announced)"
            ",mtime=VALUES(mtime)",
            update_heavy_peer_buffer.str()
        ));
        update_heavy_peer_buffer.clear();
    }
    buf_lock.unlock();

    if (!update_light_peer_buffer.empty()) {
        // See comment above
        if (qsize >= 1000) {
            std::lock_guard<std::mutex> q_lock(peer_queue_lock);
            peer_queue.pop();
            logger->error("Peer queue overflowed, update lost");
        } else {
            qsize_added += 1;
        }
        std::lock_guard<std::mutex> q_lock(peer_queue_lock);
        peer_queue.push(fmt::format(
            "INSERT INTO xbt_files_users(uid,fid,timespent,announced,peer_id,mtime)"
            "VALUES {}  ON DUPLICATE KEY UPDATE upspeed=0,downspeed=0"
            ",timespent=VALUES(timespent),announced=VALUES(announced)"
            ",mtime=VALUES(mtime)",
            update_light_peer_buffer.str()
        ));
        update_light_peer_buffer.clear();
    }
    buf_light_lock.unlock();
    stats.peer_queue_size = qsize + qsize_added;

    if (!peer_flush_active) {
        std::thread thread([this]() {
            do_flush("peer", peer_queue, peer_queue_lock, peer_flush_active, stats.peer_queue_size);
        });
        thread.detach();
    }
}

void mysql::flush_snatches() {
    std::unique_lock<std::mutex> q_lock(snatch_queue_lock);
    size_t qsize = snatch_queue.size();
    if (verbose_flush || qsize > 0) {
        logger->info("Snatch flush queue size: {}, next query length: {}", qsize, snatch_queue.front().size());
    }
    q_lock.unlock();

    std::unique_lock<std::mutex> buf_lock(snatch_buffer_lock);
    if (readonly) {
        update_snatch_buffer.clear();
        return;
    }
    if (update_snatch_buffer.empty() && qsize == 0) {
        return;
    }
    if (!update_snatch_buffer.empty()) {
        std::lock_guard<std::mutex> q_lock(snatch_queue_lock);
        snatch_queue.push(fmt::format(
            "INSERT IGNORE INTO xbt_snatched (uid, fid, tstamp, IP) VALUES {}",
            update_snatch_buffer.str()
        ));
        update_snatch_buffer.clear();
        stats.snatch_queue_size = qsize + 1;
    }
    buf_lock.unlock();

    if (!snatch_flush_active) {
        std::thread thread([this]() {
            do_flush("snatch", snatch_queue, snatch_queue_lock, snatch_flush_active, stats.snatch_queue_size);
        });
        thread.detach();
    }
}

void mysql::flush_tokens() {
    std::unique_lock<std::mutex> q_lock(token_queue_lock);
    size_t qsize = token_queue.size();
    if (verbose_flush || qsize > 0) {
        logger->info("Token flush queue size: {}, next query length: {}", qsize, token_queue.front().size());
    }
    q_lock.unlock();

    std::unique_lock<std::mutex> buf_lock(token_buffer_lock);
    if (readonly) {
        update_token_buffer.clear();
        return;
    }
    if (update_token_buffer.empty() && qsize == 0) {
        return;
    }
    if (!update_token_buffer.empty()) {
        std::lock_guard<std::mutex> q_lock(token_queue_lock);
        token_queue.push(fmt::format(
            "INSERT INTO users_freeleeches(UserID,TorrentID,Downloaded)VALUES"
            "{} ON DUPLICATE KEY UPDATE Downloaded=Downloaded+VALUES(Downloaded)",
            update_token_buffer.str()
        ));
        update_token_buffer.clear();
        stats.token_queue_size = qsize + 1;
    }
    buf_lock.unlock();

    if (!token_flush_active) {
        std::thread thread([this]() {
            do_flush("token", token_queue, token_queue_lock, token_flush_active, stats.token_queue_size);
        });
        thread.detach();
    }
}

void mysql::flush_torrents() {
    std::unique_lock<std::mutex> q_lock(torrent_queue_lock);
    size_t qsize = torrent_queue.size();
    if (verbose_flush || qsize > 0) {
        logger->info("Torrent flush queue size: {}, next query length: {}", qsize, torrent_queue.front().size());
    }
    q_lock.unlock();

    std::unique_lock<std::mutex> buf_lock(torrent_buffer_lock);
    if (readonly) {
        update_torrent_buffer.clear();
        return;
    }
    if (update_torrent_buffer.empty() && qsize == 0) {
        return;
    }
    if (!update_torrent_buffer.empty()) {
        std::lock_guard<std::mutex> q_lock(torrent_queue_lock);
        torrent_queue.push(fmt::format(
            "INSERT INTO torrents_leech_stats"
            "(TorrentID,Seeders,Leechers,Snatched,Balance)VALUES{}"
            "ON DUPLICATE KEY UPDATE Seeders=VALUES(Seeders),Leechers=VALUES(Leechers)"
            ",Snatched=Snatched+VALUES(Snatched),Balance=VALUES(Balance)"
            ",last_action=IF(VALUES(Seeders)>0,now(),last_action)",
            update_torrent_buffer.str()
        ));
        update_torrent_buffer.clear();
    }
    buf_lock.unlock();

    stats.torrent_queue_size = qsize + 1;
    if (!torrent_flush_active) {
        std::thread thread([this]() {
            do_flush("torrent", torrent_queue, torrent_queue_lock, torrent_flush_active, stats.torrent_queue_size);
        });
        thread.detach();
    }
}

void mysql::flush_users() {
    std::unique_lock<std::mutex> q_lock(user_queue_lock);
    size_t qsize = user_queue.size();
    if (verbose_flush || qsize > 0) {
        logger->info("User flush queue size: {}, next query length: {}", qsize, user_queue.front().size());
    }
    q_lock.unlock();

    std::unique_lock<std::mutex> buf_lock(user_buffer_lock);
    if (readonly) {
        update_user_buffer.clear();
        return;
    }
    if (update_user_buffer.empty() && qsize == 0) {
        return;
    }
    if (!update_user_buffer.empty()) {
        std::lock_guard<std::mutex> q_lock(user_queue_lock);
        user_queue.push(fmt::format(
            "INSERT INTO users_leech_stats(UserID,Uploaded,Downloaded)VALUES{}"
            "ON DUPLICATE KEY UPDATE Uploaded=Uploaded+VALUES(Uploaded)"
            ",Downloaded=Downloaded+VALUES(Downloaded)",
            update_user_buffer.str()
        ));
        update_user_buffer.clear();
        stats.user_queue_size = qsize + 1;
    }
    buf_lock.unlock();

    if (!user_flush_active) {
        std::thread thread([this]() {
            do_flush("user", user_queue, user_queue_lock, user_flush_active, stats.user_queue_size);
        });
        thread.detach();
    }
}

void mysql::do_flush(const char *name, std::queue<std::string> &queue, std::mutex &mtx, bool &active, std::atomic<uint32_t>& counter) {
    active = true;
    try {
        std::unique_lock<std::mutex> q_lock(mtx);
        size_t q_size = queue.size();
        q_lock.unlock();

        mysqlpp::Connection c = create_connection();
        std::string sql;
        while (q_size > 0) {
            try {
                std::unique_lock<std::mutex> q_lock(mtx);
                sql = queue.front();
                q_lock.unlock();
                mysqlpp::Query query = c.query(sql);
                if (!query.exec()) {
                    logger->info("{} flush failed ({} remain)", name, q_size);
                    std::this_thread::sleep_for(std::chrono::seconds(3));
                    break;
                }
                q_lock.lock();
                queue.pop();
                q_size = queue.size();
                q_lock.unlock();
                counter -= 1;
            }
            catch (const mysqlpp::BadQuery &er) {
                logger->error("SQL error: {} in {} flush with a qlength: {} queue size: {} sql=[{}]",
                    er.what(), name, queue.front().size(), q_size, sql
                );
                std::this_thread::sleep_for(std::chrono::seconds(3));
                break;
            } catch (const mysqlpp::Exception &er) {
                logger->error("DB error: {} in {} flush with a qlength: {} queue size: {}",
                    er.what(), name, queue.front().size(), q_size
                );
                std::this_thread::sleep_for(std::chrono::seconds(3));
                break;
            }
        }
    }
    catch (const mysqlpp::Exception &er) {
        logger->error("General DB error in {} flush: {}", name, er.what());
    }
    active = false;
}
