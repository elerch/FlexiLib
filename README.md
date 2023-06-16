<img src="FlexiLib.svg" width="100px" />

FlexiLib
========

This is a web server written with the following goals:

* Low memory consumption
* Low latency
* Flexible "reverse proxy" capabilities
* Ability to simulate FAAS capabilities of various online providers (AWS, CloudFlare, etc)

This last point is indirectly supported through the ability of the server to
load, at run time, dynamic libraries to support requests. It will also reload
these libraries after any in flight requests have completed, to support the
experience of developing new libaries.

Libraries can be written in any programming language that supports a standard
Linux C-Based calling convention, which is to say, nearly every programming
language.

This project provides slightly better development and performance characteristics
if the library used is written in [zig](https://ziglang.org). An example zig-based
library can be found in src/main-lib.zig.

Architecture
------------

This library assumes the use of Linux as a host. While the primary engine is not
tied to Linux, the file watcher module uses inotify and friends and will not
work outside that OS. PRs are welcome.

The system is built with a pre-release version of zig, currently zig version
[0.11.0-dev.3312+ab37ab33c](https://github.com/marler8997/zig-unofficial-releases#0110-dev3312ab37ab33c-summary).
This version has web server in the standard library, so it is useful.

To achieve the lowest latency possible, this server loads dynamic libraries
using [dlopen(3)](https://linux.die.net/man/3/dlopen) based on a configuration
file in the current working directory called `proxy.ini`. An example of the
configuration is in this directory, and it is relatively simple string prefix
matching, again, for speed.

On startup, a thread pool will be created. Request paths and header matching
is loaded from the configuration file, and file watches are initiated on all
libraries mentioned in the configuration file. Libraries are loaded on demand
when a request arrives that needs the library. When a library changes for a new
version, the file watcher will take note and unload the previous version.

Changes to the configuration file are not watched, relying instead on a HUP
signal to force a reload. At that point, all libraries ("executors") are
unloaded, and configuration is re-read.

As libraries are loaded directly into main process space, bugs in the libraries
can and will crash the engine. As such, some supervisory process (dockerd,
systemd, etc) should monitor and restart if necessary.

Security
--------

There is little attempt to secure libraries from interfering with the current
thread or even the main process. As such, the libraries should be fully trusted.
However, libraries themselves may be hardened to run other non-trusted code.
For example: A "I run WASM code" library may be written to create a WASM VM and
run user-supplied WASM code. In that case, the "I run WASM code" library is
trusted, although the code it runs may not be.

Configuration
-------------

Very little has been done so far in terms of configuration. By default, the
number of threads created to serve requests is equal to the number of CPUs
reported by the system (although thread count is limited to 4 threads when
compiled in debug mode). This can be controlled with the environment variable
`SERVER_THREAD_COUNT`.

The port by default is 8069, although this can be set with the `PORT`
environment variable. Future plans include an environment variable for IP
address as well as the amount of pre-allocated memory for response data (currently
hardcoded to 8k/thread). Pre-allocated memory reduces the number of system
calls required for memory allocation, and pre-allocation/allocation statistics
per request are reported in the logs. The current pre-allocation provides
approximately 4k per request without requiring system calls.

Logs
----

Request logs are sent to standard out, and are likely to change. Here is a sample:

```
127.0.0.1:59940 - - "GET / HTTP/1.1" 200 ttfb 2000.420ms 11 ttlb 2000.568ms (pre-alloc: 1569, alloc: 4350)
```

The first part mirrors common logs from Apache/nginx.

ttfb: Time to first byte. This represents the number of ms of processing within the library
ttlb: Time to last byte. This includes processing as well a transmission of data
pre-alloc: The amount of memory actually pre-allocated (1k is just a minimum and the system may allocate more)
alloc: The amount of memory actually allocated during the request

