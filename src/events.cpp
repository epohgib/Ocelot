// Copyright [2017-2026] Orpheus

#include <spdlog/spdlog.h>

#include <cerrno>

#include "ocelot.h"
#include "config.h"
#include "db.h"
#include "worker.h"
#include "schedule.h"
#include "response.h"
#include "events.h"

std::mutex peak_open_mutex;

// Define the connection mother (first half) and connection middlemen (second half)

//---------- Connection mother - spawns middlemen and lets them deal with the connection

connection_mother::connection_mother(config * conf, worker * w, site_comm * sc_obj, schedule * sched) : work(w), logger(spdlog::get("logger")) {
    // Handle config stuff first
    load_config(conf);

    listen_socket = create_listen_socket();

    // We failed to create the socket, so no point in running Ocelot
    if (listen_socket == 0) {
        logger->critical("failed to create listen socket for Ocelot, exiting");
        exit(1);
    }

    listen_event.set<connection_mother, &connection_mother::handle_connect>(this);
    listen_event.start(listen_socket, ev::READ);
    // Create libev timer
    schedule_event.set<schedule, &schedule::handle>(sched);
    schedule_event.start(sched->schedule_interval, sched->schedule_interval);  // After interval, every interval
}

void connection_mother::load_config(config * conf) {
    listen_port        = conf->get_uint("listen_port");
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
    load_config(conf);
    if (old_listen_port != listen_port) {
        logger->info(
            "changing listen port from {} to {}",
            old_listen_port, listen_port
        );
        int new_listen_socket = create_listen_socket();
        if (new_listen_socket != 0) {
            listen_event.stop();
            listen_event.start(new_listen_socket, ev::READ);
            close(listen_socket);
            listen_socket = new_listen_socket;
        } else {
            logger->error("failed to create new listen socket when reloading config");
        }
    } else if (old_max_connections != max_connections) {
        listen(listen_socket, max_connections);
    }
}

int connection_mother::create_listen_socket() {
    sockaddr_in address = {0};
    int new_listen_socket = socket(AF_INET, SOCK_STREAM, 0);

    // Stop old sockets from hogging the port
    int yes = 1;
    if (setsockopt(new_listen_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        logger->error("failed to reuse socket: {}", strerror(errno));
        return 0;
    }

    // Get ready to bind
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(listen_port);

    // Bind
    if (bind(new_listen_socket, reinterpret_cast<struct sockaddr*>(&address), sizeof(address)) == -1) {
        logger->error("failed to bind to listen socket: {}", strerror(errno));
        return 0;
    }

    // Listen
    if (listen(new_listen_socket, max_connections) == -1) {
        logger->error("failed to listen on socket: {}", strerror(errno));
        return 0;
    }

    // Set non-blocking
    int flags = fcntl(new_listen_socket, F_GETFL);
    if (flags == -1) {
        logger->error("failed to read socket flags: {}", strerror(errno));
        return 0;
    }
    if (fcntl(new_listen_socket, F_SETFL, flags | O_NONBLOCK) == -1) {
        logger->error("failed to set listen socket non-blocking: {}", strerror(errno));
        return 0;
    }

    return new_listen_socket;
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
        new connection_middleman(listen_socket, work, this);
    }
}

connection_mother::~connection_mother()
{
    close(listen_socket);
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
            sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            getpeername(connect_sock, reinterpret_cast<sockaddr *>(&client_addr), &addr_len);

            //--- CALL WORKER
            response = work->work(request, client_addr.sin_addr.s_addr, client_opts);
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
