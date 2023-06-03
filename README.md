[![](FlexiLib.png)](FlexiLib.png)

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

TODO:

We assume Linux.
To achieve the lowest latency possible and eliminate the proliferation, The architecture of this server is setup 

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

Future plans include an environment variable for IP address and port to listen
on, as well as the amount of pre-allocated memory for response data (currently
hardcoded to 1k/thread). Pre-allocated memory reduces the number of system
calls required for memory allocation, and pre-allocation/allocation statistics
per request are reported in the logs.

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

