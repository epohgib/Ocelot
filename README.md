# Ocelot

Ocelot is a BitTorrent tracker written in C++ for the [Gazelle](http://github.com/OPSnet/Gazelle) project.
It supports requests over TCP and tracks IPv4 and IPv6 peers (BEP 07). IPv6 is
opt-in: enable it globally with `enable_ipv6` and per user with
`users_main.track_ipv6`.

### IPv6 tracking model

The address observed on the connection (or in the trusted real-IP header) is
authoritative for its own family: an announce coming over IPv4 is always
tracked on that IPv4 address, and likewise for IPv6. The client may advertise
its other family with the `ipv6=` / `ipv4=` / `ip=` announce parameters, which
are accepted only when they are globally routable addresses and only when they
fill the family the connection did not come from. Both families are then
offered from a single peer: `peers6` (BEP 07) to IPv6 announcers, `peers`
(BEP 03) to everyone. Private, loopback, link-local, multicast, reserved and
documentation ranges are rejected for both families.

Known limitation, shared with Radiance: peers are keyed by (peer id, user), so
a client that announces over both families *without* those parameters
overwrites its stored address set on each announce. Clients that advertise the
other family keep both endpoints; most current clients do.

These choices differ deliberately from
[Empornium/Radiance](https://github.com/Empornium/Radiance): there the
parameters can override the observed family, an unparseable real-IP header
falls back silently to the socket address, and the rejected range set is
narrower (it misses fd00::/8 and accepts multicast/broadcast).

## Ocelot Compile-time Dependencies

* [CMake](https://cmake.org/) (3.12+ required)
* [GCC/G++](http://gcc.gnu.org/) (12+ recommended) or [Clang](https://clang.llvm.org/) (5+ minimum)
* [Boost](http://www.boost.org/) (1.66+ required for `boost::asio::io_context`)
* [libev](http://software.schmorp.de/pkg/libev.html) (4.0+ required)
* [libfmt](https://github.com/fmtlib/fmt) (8.1+ required)
* [MySQL++](http://tangentsoft.net/mysql++/) (3.2.0+ required)
* [MySQL Client](https://dev.mysql.com/downloads/c-api/) (8.0+ recommended)
* [jemalloc](http://jemalloc.net/) (5.0+ optional, but strongly recommended)
* [TCMalloc](http://goog-perftools.sourceforge.net/doc/tcmalloc.html) (optional, alternative to jemalloc)

## Installation

### Debian Bookworm
```bash
sudo apt-get install \
    build-essential \
    cmake \
    default-libmysqlclient-dev \
    libboost-iostreams-dev \
    libboost-system-dev \
    libev-dev \
    libfmt-dev \
    libjemalloc-dev \
    libmysql++-dev \
	netcat-traditional \
    pkg-config
cmake . -B build
make -C build
```

The [Gazelle installation guides](https://github.com/WhatCD/Gazelle/wiki/Gazelle-installation) include instructions for installing Ocelot as a part of the Gazelle project.

### Docker

```bash
docker build . -t ocelot
docker run -v $(pwd)/ocelot.conf:/srv/ocelot.conf ocelot
```

### Standalone Installation

* Build the binary

        cmake . -B build && make -C build

(Technically there is no need to run cmake if there are no library changes, but it is instant).

* Create the following tables according to the [Gazelle database schema](https://raw.githubusercontent.com/WhatCD/Gazelle/master/gazelle.sql):
 - `torrents`
 - `torrents_leech_stats`
 - `users_freeleeches`
 - `users_leech_stats`
 - `users_main`
 - `xbt_client_whitelist`
 - `xbt_files_users`
 - `xbt_snatched`

* Edit `ocelot.conf` to your liking.

## Running Ocelot

### Run-time options:

* `-c <path/to/ocelot.conf>` - Path to config file. If unspecified, the current working directory is used.
* `-d` or `--daemonize` - Run as a daemon in the background.
* `-v` - Print queue status every time a flush is initiated.
* `-V` or `--version` - Print the version
* `-X` or `--ignore-xff` - Ignore the X-Forwarded-For header

### Notes:

By default, ocelot will trust X-Forwarded-For headers as the source for client
IP addresses. If ocelot is running behind a proxy, this is the desired behavior.
(And if it is not, how are you performing SSL termination?)

The header that is trusted is configurable with `real_ip_header`. Behind
Cloudflare it must be set to `CF-Connecting-IP`: Cloudflare appends the
connecting address to a client-supplied X-Forwarded-For, so its first token is
under the client's control. Only the first token of the configured header is
used.

If, for whatever reason, ocelot is not behind a proxy, this would allow an
attacker to insert a bogus X-Forwarded-For header and set the IP address to a
different IP address under their control. The `--ignore-xff` flag prevents this.

You can run a test ocelot daemon alongside a production daemon by specifying
a separate configuration file, and setting `readonly = true`. This will
prevent the database peer tables from being reset.

### Signals

* `SIGHUP` - Reload config
* `SIGUSR1` - Reload torrent list, user list and client whitelist

The user list (protection, leech status, `track_ipv6`) is read from the
database only at startup and on `SIGUSR1`; there is no periodic reload. A change
made directly to `users_main`, instead of being pushed through the `update_user`
API action, therefore takes effect only after a reload.
