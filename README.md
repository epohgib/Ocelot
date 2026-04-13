# Ocelot

Ocelot is a BitTorrent tracker written in C++ for the [Gazelle](http://github.com/OPSnet/Gazelle) project.
It supports requests over TCP and can only track IPv4 peers.

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

If, for whatever reason, ocelot is not behind a proxy, this would allow an
attacker to insert a bogus X-Forwarded-For header and set the IP address to a
different IP address under their control. The `--ignore-xff` flag prevents this.

You can run a test ocelot daemon alongside a production daemon by specifying
a separate configuration file, and setting `readonly = true`. This will
prevent the database peer tables from being reset.

### Signals

* `SIGHUP` - Reload config
* `SIGUSR1` - Reload torrent list, user list and client whitelist
