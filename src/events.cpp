// Copyright [2017-2026] Orpheus

#include <spdlog/spdlog.h>

#include <cerrno>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "ocelot.h"
#include "config.h"
#include "db.h"
#include "worker.h"
#include "misc_functions.h"
#include "schedule.h"
#include "response.h"
#include "events.h"

std::mutex peak_open_mutex;

// Define the connection mother (first half) and connection middlemen (second half)

//---------- Connection mother - spawns middlemen and lets them deal with the connection

connection_mother::connection_mother(config * conf, worker * w, site_comm * sc_obj, schedule * sched) : work(w), logger(spdlog::get("logger")) {
    // Handle config stuff first
    load_config(conf);

    // We failed to create any socket, so no point in running Ocelot
    if (create_listen_socket() != 0) {
        logger->critical("failed to create listen socket for Ocelot, exiting");
        exit(1);
    }

    for (const int listen_socket : listen_sockets) {
        auto *listen_event = new ev::io;
        listen_event->set<connection_mother, &connection_mother::handle_connect>(this);
        listen_event->start(listen_socket, ev::READ);
        listen_events[listen_socket] = listen_event;
    }

    // Create libev timer
    schedule_event.set<schedule, &schedule::handle>(sched);
    schedule_event.start(sched->schedule_interval, sched->schedule_interval);  // After interval, every interval
}

void connection_mother::load_config(config * conf) {
    listen_port        = conf->get_uint("listen_port");
    listen_hosts       = split(conf->get_str("listen_host"), ' ');
    max_connections    = conf->get_uint("max_connections");
    max_middlemen      = conf->get_uint("max_middlemen");
    connection_timeout = conf->get_uint("connection_timeout");
    keepalive_timeout  = conf->get_uint("keepalive_timeout");
    max_read_buffer    = conf->get_uint("max_read_buffer");
    max_request_size   = conf->get_uint("max_request_size");
}

void connection_mother::reload_config(config * conf) {
    unsigned int old_listen_port = listen_port;
    unsigned int old_max_connections = max_connections;
    std::vector<std::string> old_listen_hosts = listen_hosts;
    load_config(conf);

    if (old_listen_port == listen_port && old_listen_hosts == listen_hosts) {
        if (old_max_connections != max_connections) {
            for (const int listen_socket : listen_sockets) {
                listen(listen_socket, max_connections);
            }
        }
        return;
    }

    logger->info(
        "listen configuration changed (port {} => {}), rebuilding listen sockets",
        old_listen_port, listen_port
    );

    // Tear the old listeners down first: binding a new socket on the same port
    // while the old one is still open fails with EADDRINUSE.
    for (auto const &entry : listen_events) {
        entry.second->stop();
        delete entry.second;
    }
    listen_events.clear();
    std::vector<int> old_listen_sockets = listen_sockets;
    listen_sockets.clear();
    for (const int listen_socket : old_listen_sockets) {
        close(listen_socket);
    }

    if (create_listen_socket() != 0) {
        // Put the previous configuration back rather than running deaf.
        logger->error("failed to rebuild listen sockets, restoring the previous configuration");
        for (const int listen_socket : listen_sockets) {
            close(listen_socket);
        }
        listen_sockets.clear();
        listen_port = old_listen_port;
        listen_hosts = old_listen_hosts;
        if (create_listen_socket() != 0) {
            logger->critical("failed to restore listen sockets, no listener is active");
            return;
        }
    }

    for (const int listen_socket : listen_sockets) {
        auto *listen_event = new ev::io;
        listen_event->set<connection_mother, &connection_mother::handle_connect>(this);
        listen_event->start(listen_socket, ev::READ);
        listen_events[listen_socket] = listen_event;
    }
}

int connection_mother::create_listen_socket() {
    if (listen_hosts.empty()) {
        listen_hosts.push_back("*");
    }

    bool listening = false;
    for (const std::string &listen_host : listen_hosts) {
        if (listen_host.empty()) {
            continue;
        }
        if (listen_host.compare(0, 5, "unix:") == 0) {
            if (create_unix_server(listen_host.substr(5)) != 0) {
                continue;
            }
        } else if (create_tcp_server(listen_port, listen_host) != 0) {
            continue;
        }
        listening = true;
    }

    if (!listening) {
        logger->critical("configured to not listen anywhere");
        return 1;
    }
    return 0;
}

int connection_mother::create_tcp_server(unsigned int port, const std::string &ip) {
    struct addrinfo hints = {};
    struct addrinfo *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    const char *bindaddr = (ip.empty() || ip == "*") ? nullptr : ip.c_str();

    std::string port_str = std::to_string(port);
    int err = getaddrinfo(bindaddr, port_str.c_str(), &hints, &res);
    if (err != 0) {
        logger->error("failed to resolve listen host '{}': {}", ip, gai_strerror(err));
        return 1;
    }

    int created = 0;
    for (struct addrinfo *p = res; p != nullptr; p = p->ai_next) {
        int new_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (new_socket == -1) {
            logger->warn("failed to open socket for listen host '{}': {}", ip, strerror(errno));
            continue;
        }

#if defined IPV6_V6ONLY
        // One socket per family: the IPv4 and IPv6 listeners must not overlap.
        if (p->ai_family == AF_INET6) {
            int yes = 1;
            if (setsockopt(new_socket, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes)) == -1) {
                logger->warn("failed to set IPV6_V6ONLY: {}", strerror(errno));
                close(new_socket);
                continue;
            }
        }
#endif

        int yes = 1;
        if (setsockopt(new_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
            logger->warn("failed to set SO_REUSEADDR: {}", strerror(errno));
            close(new_socket);
            continue;
        }

        int flags = fcntl(new_socket, F_GETFL);
        if (flags == -1 || fcntl(new_socket, F_SETFL, flags | O_NONBLOCK) == -1) {
            logger->warn("failed to set listen socket non-blocking: {}", strerror(errno));
            close(new_socket);
            continue;
        }

        if (bind(new_socket, p->ai_addr, p->ai_addrlen) == -1) {
            logger->warn("failed to bind listen socket: {}", strerror(errno));
            close(new_socket);
            continue;
        }

        if (listen(new_socket, max_connections) == -1) {
            logger->warn("failed to listen on socket: {}", strerror(errno));
            close(new_socket);
            continue;
        }

        char ip_value[INET6_ADDRSTRLEN] = {0};
        if (p->ai_family == AF_INET) {
            struct sockaddr_in *s = reinterpret_cast<struct sockaddr_in *>(p->ai_addr);
            inet_ntop(AF_INET, &s->sin_addr, ip_value, sizeof(ip_value));
            logger->info("listening with IPv4 socket on {}:{}", ip_value, port);
        } else {
            struct sockaddr_in6 *s6 = reinterpret_cast<struct sockaddr_in6 *>(p->ai_addr);
            inet_ntop(AF_INET6, &s6->sin6_addr, ip_value, sizeof(ip_value));
            logger->info("listening with IPv6 socket on [{}]:{}", ip_value, port);
        }

        listen_sockets.push_back(new_socket);
        created++;
    }
    freeaddrinfo(res);

    if (created == 0) {
        logger->error("failed to bind any socket for listen host '{}'", ip);
        return 1;
    }
    return 0;
}

int connection_mother::create_unix_server(const std::string &path) {
    struct sockaddr_un unix_address = {};
    unix_address.sun_family = AF_UNIX;
    strncpy(unix_address.sun_path, path.c_str(), sizeof(unix_address.sun_path) - 1);

    // A stale socket file from a previous run would make bind() fail, but
    // unlinking blindly could steal the socket of a live instance: probe it
    // first and only clean up a dead socket file. Never touch non-socket
    // files that happen to sit at the configured path.
    struct stat st;
    if (stat(path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode)) {
        bool alive = false;
        int probe = socket(AF_UNIX, SOCK_STREAM, 0);
        if (probe != -1) {
            alive = connect(probe, reinterpret_cast<struct sockaddr *>(&unix_address), sizeof(unix_address)) == 0;
            close(probe);
        }
        if (alive) {
            logger->error("unix socket {} is already served by another process", path);
            return 1;
        }
        unlink(path.c_str());
    }

    int new_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (new_socket == -1) {
        logger->error("failed to open unix socket: {}", strerror(errno));
        return 1;
    }

    int flags = fcntl(new_socket, F_GETFL);
    if (flags == -1 || fcntl(new_socket, F_SETFL, flags | O_NONBLOCK) == -1) {
        logger->error("failed to set unix socket non-blocking: {}", strerror(errno));
        close(new_socket);
        return 1;
    }

    if (bind(new_socket, reinterpret_cast<struct sockaddr *>(&unix_address), sizeof(unix_address)) == -1) {
        logger->error("failed to bind unix socket {}: {}", path, strerror(errno));
        close(new_socket);
        return 1;
    }

    // From here on the bind() created the filesystem entry: every failure
    // must unlink it, or a dead socket file is left behind.
    if (listen(new_socket, max_connections) == -1) {
        logger->error("failed to listen on unix socket {}: {}", path, strerror(errno));
        close(new_socket);
        unlink(path.c_str());
        return 1;
    }

    // 0660: only the tracker's user/group may talk to the socket. It sits in
    // front of the trusted real-IP header, so it must not be world-writable.
    if (chmod(path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) == -1) {
        logger->error("chmod on unix socket {} failed: {}", path, strerror(errno));
        close(new_socket);
        unlink(path.c_str());
        return 1;
    }

    logger->info("listening with unix socket on {}", path);
    listen_sockets.push_back(new_socket);
    unix_socket_path = path;
    return 0;
}

void connection_mother::run() {
    logger->info("listening on port {}, starting event loop!", listen_port);
    ev_loop(ev_default_loop(0), 0);
}

void connection_mother::handle_connect(ev::io &watcher, int events_flags) {
    // Spawn a new middleman
    if (stats.open_connections < max_middlemen) {
        stats.opened_connections++;
        {
            const std::lock_guard<std::mutex> lock(peak_open_mutex);
            unsigned int current_open = stats.open_connections++;
            if (stats.peak_connections < current_open) {
                stats.peak_connections = current_open;
            }
        }
        new connection_middleman(watcher.fd, work, this);
    }
}

connection_mother::~connection_mother()
{
    for (auto const &entry : listen_events) {
        entry.second->stop();
        delete entry.second;
    }
    for (const int listen_socket : listen_sockets) {
        close(listen_socket);
    }
    if (!unix_socket_path.empty()) {
        unlink(unix_socket_path.c_str());
    }
}


//---------- Connection middlemen - these little guys live until their connection is closed

connection_middleman::connection_middleman(int &listen_socket, worker * w, connection_mother * mother_arg) :
    written(0), mother(mother_arg), work(w)
{
    connect_sock = accept(listen_socket, NULL, NULL);
    if (connect_sock == -1) {
        spdlog::get("logger")->error("socket accept failed, errno {} ({})", errno, strerror(errno));
        delete this;
        return;
    }

    // Set non-blocking
    int flags = fcntl(connect_sock, F_GETFL);
    if (flags == -1) {
        spdlog::get("logger")->warn("failed to read connect socket flags");
    }
    if (fcntl(connect_sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        spdlog::get("logger")->warn("failed to set connect socket non-blocking");
    }

    // Get their info
    request.reserve(mother->max_read_buffer);
    written = 0;

    read_event.set<connection_middleman, &connection_middleman::handle_read>(this);
    read_event.start(connect_sock, ev::READ);

    // Let the socket timeout in timeout_interval seconds
    timeout_event.set<connection_middleman, &connection_middleman::handle_timeout>(this);
    timeout_event.set(mother->connection_timeout, mother->keepalive_timeout);
    timeout_event.start();
}

connection_middleman::~connection_middleman() {
    close(connect_sock);
    stats.open_connections--;
}

// Handler to read data from the socket, called by event loop when socket is readable
void connection_middleman::handle_read(ev::io &watcher, int events_flags) {
    char buffer[mother->max_read_buffer + 1] = {0};
    int bytes_read = recv(connect_sock, &buffer, mother->max_read_buffer, 0);

    if (bytes_read <= 0) {
        delete this;
        return;
    }
    stats.bytes_read += bytes_read;
    request.append(buffer, bytes_read);
    size_t request_size = request.size();
    if (request_size > mother->max_request_size || (request_size >= 4 && request.compare(request_size - 4, std::string::npos, "\r\n\r\n") == 0)) {
        stats.requests++;
        read_event.stop();
        client_opts.gzip = false;
        client_opts.html = false;
        client_opts.http_close = true;

        if (request_size > mother->max_request_size) {
            shutdown(connect_sock, SHUT_RD);
            response = error("GET string too long", client_opts);
        } else {
            struct sockaddr_storage client_addr = {};
            socklen_t addr_len = sizeof(client_addr);
            getpeername(connect_sock, reinterpret_cast<sockaddr *>(&client_addr), &addr_len);

            client_addr_t remote_addr = {"", AF_UNSPEC};
            if (client_addr.ss_family == AF_INET) {
                struct sockaddr_in *s = reinterpret_cast<struct sockaddr_in *>(&client_addr);
                char ip[INET_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip));
                remote_addr = {ip, AF_INET};
            } else if (client_addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *s6 = reinterpret_cast<struct sockaddr_in6 *>(&client_addr);
                char ip[INET6_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof(ip));
                std::string ip_str(ip);
                // An IPv4-mapped address is IPv4, and ipv6_is_public() would
                // reject it as such: demote it before the worker sees it.
                if (ip_str.compare(0, 7, "::ffff:") == 0) {
                    remote_addr = {ip_str.substr(7), AF_INET};
                } else {
                    remote_addr = {ip_str, AF_INET6};
                }
            } else if (client_addr.ss_family == AF_UNIX) {
                // A unix socket has no address of its own; the worker requires
                // X-Forwarded-For in that case.
                remote_addr = {"", AF_UNIX};
            } else {
                shutdown(connect_sock, SHUT_RD);
                response = error("Unknown domain socket", client_opts);
                request.clear();
                write_event.set<connection_middleman, &connection_middleman::handle_write>(this);
                write_event.start(connect_sock, ev::WRITE);
                return;
            }

            //--- CALL WORKER
            response = work->work(request, remote_addr, client_opts);
            request.clear();
        }

        // Find out when the socket is writeable.
        // The loop in connection_mother will call handle_write when it is.
        write_event.set<connection_middleman, &connection_middleman::handle_write>(this);
        write_event.start(connect_sock, ev::WRITE);
    }
}

// Handler to write data to the socket, called by event loop when socket is writeable
void connection_middleman::handle_write(ev::io &watcher, int events_flags) {
    int bytes_written = send(
        connect_sock,
        response.c_str() + written,
        response.size() - written,
        MSG_NOSIGNAL
    );
    if (bytes_written == -1) {
        return;
    }
    stats.bytes_written += bytes_written;
    written += bytes_written;
    if (written == response.size()) {
        write_event.stop();
        if (client_opts.http_close) {
            timeout_event.stop();
            delete this;
            return;
        }
        timeout_event.again();
        read_event.start();
        response.clear();
        written = 0;
    }
}

// After a middleman has been alive for timeout_interval seconds, this is called
void connection_middleman::handle_timeout(ev::timer &watcher, int events_flags) {
    timeout_event.stop();
    read_event.stop();
    write_event.stop();
    delete this;
}
