const std = @import("std");
const builtin = @import("builtin");
const interface = @import("interface.zig");
const Watch = @import("Watch.zig");
const config = @import("config.zig");

const log = std.log.scoped(.main);

// logging options
pub const std_options = struct {
    pub const log_level = switch (builtin.mode) {
        .Debug => .debug,
        .ReleaseSafe => .info,
        .ReleaseFast, .ReleaseSmall => .err,
    };

    pub const log_scope_levels = &[_]std.log.ScopeLevel{
        .{ .scope = .watch, .level = .info },
    };
};

const serveFn = *const fn (*interface.Request) ?*interface.Response;
const zigInitFn = *const fn (*anyopaque) void;
const requestDeinitFn = *const fn () void;

const timeout = 250;

var watcher = Watch.init(executorChanged);
var watcher_thread: ?std.Thread = null;

// Timer used by processRequest to provide ttfb/ttlb data in output
var timer: ?std.time.Timer = null;

const FullReturn = struct {
    response: []u8,
    executor: *Executor,
};

// Executor structure, including functions that were found in the library
// and accounting. Also contains match data to determine if an executor
// applies
const Executor = struct {
    // configuration
    match_data: []const u8,
    path: [:0]const u8,

    // fields used at runtime to do real work
    library: ?*anyopaque = null,
    serveFn: ?serveFn = null,
    zigInitFn: ?zigInitFn = null,
    requestDeinitFn: ?requestDeinitFn = null,

    // fields used for internal accounting
    watch: ?usize = null,
    drain_in_progress: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(false),
    load_in_progress: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(false),
    requests_in_flight: std.atomic.Atomic(usize) = std.atomic.Atomic(usize).init(0),
};

const SERVE_FN_NAME = "handle_request";
const PORT = 8069; // TODO: Update based on environment variable
var response_preallocation_kb: usize = 8; // We used to need 1kb, but the changes between zig 465272921 and fd6200eda
// ends up allocating about 4kb. Bumping this to 8kb gives plugins some room

var executors: []Executor = undefined;
var parsed_config: config.ParsedConfig = undefined;

/// Serves a single request. Finds executor, marshalls request data for the C
/// interface, calls the executor and marshalls data back
fn serve(allocator: *std.mem.Allocator, response: *std.http.Server.Response) !*FullReturn {
    const executor = try getExecutor(response.request.target, response.request.headers);
    errdefer _ = executor.requests_in_flight.fetchSub(1, .Monotonic);
    if (executor.zigInitFn) |f|
        f(allocator);

    // Call external library
    const method_tag = @tagName(response.request.method);
    const headers = try toHeaders(allocator.*, response.request.headers);
    var request_content: []u8 = &[_]u8{};
    if (response.request.content_length) |l| {
        request_content = try response.reader().readAllAlloc(allocator.*, @as(usize, l));
    }
    log.debug("{d} bytes read from request", .{request_content.len});
    var request = interface.Request{
        .method = @constCast(method_tag[0..].ptr),
        .method_len = method_tag.len,

        .headers = headers,
        .headers_len = response.request.headers.list.items.len,

        .content = request_content.ptr,
        .content_len = request_content.len,
    };
    var serve_result = executor.serveFn.?(&request).?; // ok for this pointer deref to fail
    log.debug("target: {s}", .{response.request.target});
    log.debug("response ptr: {*}", .{serve_result.ptr});
    var slice: []u8 = serve_result.ptr[0..serve_result.len];
    log.debug("response body: {s}", .{slice});

    // Deal with results
    var content_type_added = false;
    for (0..serve_result.headers_len) |inx| {
        const head = serve_result.headers[inx];
        try response.headers.append(
            head.name_ptr[0..head.name_len],
            head.value_ptr[0..head.value_len],
        );

        // headers are case insensitive
        content_type_added = std.ascii.eqlIgnoreCase(head.name_ptr[0..head.name_len], "content-type");
    }
    if (!content_type_added)
        try response.headers.append("content-type", "text/plain");
    // target is path
    var rc = try allocator.create(FullReturn);
    rc.executor = executor;
    rc.response = slice;
    return rc;
}

/// Gets and executor based on request data
fn getExecutor(requested_path: []const u8, headers: std.http.Headers) !*Executor {
    var executor = blk: {
        for (executors) |*exec| {
            if (executorIsMatch(exec.match_data, requested_path, headers)) {
                break :blk exec;
            }
        }
        log.err("Could not find executor for target path '{s}'", .{requested_path});
        return error.NoApplicableExecutor;
    };
    while (executor.drain_in_progress.load(.Acquire)) {
        // we need to stand down and stand by
        std.atomic.spinLoopHint(); // Let CPU know we're just hanging out
        std.time.sleep(1 * std.time.ns_per_ms / 2);
    }
    // Tell everyone we're about to use this bad boy
    // While requests_in_flight is >= 0, nobody should unload the library
    _ = executor.requests_in_flight.fetchAdd(1, .Acquire);
    errdefer _ = executor.requests_in_flight.fetchSub(1, .Release);

    if (executor.serveFn != null) return executor;

    executor.library = blk: {
        if (executor.library) |l|
            break :blk l;

        // If the library is being reloaded and a bunch of requests come in,
        // we could have multiple threads racing to load
        // NOTE: I am not confident of the memory ordering here on tryCompareAndSwap
        while (executor.load_in_progress.tryCompareAndSwap(false, true, .Acquire, .Acquire)) |_| {
            // we need to stand down and stand by
            std.atomic.spinLoopHint(); // Let CPU know we're just hanging out
            std.time.sleep(1 * std.time.ns_per_ms / 2);
        }
        // we have the conch...lock others out
        defer executor.load_in_progress.store(false, .Release);

        if (executor.library) |l|
            break :blk l; // someone beat us to the race..our defer above will take care of unlocking

        log.info("library {s} requested but not loaded. Loading library", .{executor.path});
        const l = try dlopen(executor.path);
        errdefer if (std.c.dlclose(l) != 0)
            @panic("System unstable: Error after library open and cannot close");
        executor.watch = executor.watch orelse try watcher.addFileWatch(&executor.path);
        break :blk l;
    };

    // std.c.dlerror();
    const serve_fn = std.c.dlsym(executor.library.?, SERVE_FN_NAME);
    if (serve_fn == null) return error.CouldNotLoadSymbolServe;

    executor.serveFn = @ptrCast(serve_fn.?);
    loadOptionalSymbols(executor);
    return executor;
}

fn executorIsMatch(match_data: []const u8, requested_path: []const u8, headers: std.http.Headers) bool {
    if (!std.mem.containsAtLeast(u8, match_data, 1, ":")) {
        // match_data does not have a ':'. This means this is a straight path, without
        // any header requirement. We can simply return a match prefix on the
        // requested path
        const rc = std.mem.startsWith(u8, requested_path, match_data);
        if (rc) log.debug("executor match for path prefix '{s}'", .{match_data});
        return rc;
    }
    const colon = std.mem.indexOf(u8, match_data, ":").?;
    const header_needle = match_data[0..colon];
    const header_inx = headers.firstIndexOf(header_needle) orelse return false;
    // Apparently std.mem.split will return an empty first when the haystack starts
    // with the delimiter
    var split = std.mem.split(u8, std.mem.trim(u8, match_data[colon + 1 ..], "\t "), " ");
    const header_value_needle = split.first();
    const path_needle = split.next() orelse {
        std.log.warn(
            "Incorrect configuration. Header matching requires both header value and path prefix, space delimited. Key was '{s}'",
            .{match_data},
        );
        return false;
    };
    // match_data includes some sort of header match as well. We assume the
    // header match is a full match on the key (handled above)
    // but a prefix match on the value
    const request_header_value = headers.list.items[header_inx].value;
    // (shoud this be case insensitive?)
    if (!std.mem.startsWith(u8, request_header_value, header_value_needle)) return false;
    // header value matches...return the path prefix match
    const rc = std.mem.startsWith(u8, requested_path, path_needle);
    if (rc) log.debug("executor match for header and path prefix '{s}'", .{match_data});
    return rc;
}

/// Loads all optional symbols from the dynamic library. This has two entry
/// points, though the logic around the primary request handler is slighly
/// different in each case so we can't combine those two.
fn loadOptionalSymbols(executor: *Executor) void {
    if (std.c.dlsym(executor.library.?, "request_deinit")) |s| {
        executor.requestDeinitFn = @ptrCast(s);
    }
    if (std.c.dlsym(executor.library.?, "zigInit")) |s| {
        executor.zigInitFn = @ptrCast(s);
    }
}

/// Executor changed. This will be called by a sepearate thread that is
/// ultimately triggered from the operating system. This will wait for open
/// requests to that libary to complete, then lock out new requests until
/// the library is reloaded.
fn executorChanged(watch: usize) void {
    // NOTE: This will be called off the main thread
    log.debug("executor with watch {d} changed", .{watch});
    for (executors) |*executor| {
        if (executor.watch) |w| {
            if (w == watch) {
                if (executor.library) |l| {
                    executor.drain_in_progress.store(true, .Release);
                    defer executor.drain_in_progress.store(false, .Release);
                    while (executor.requests_in_flight.load(.Acquire) > 0) {
                        std.atomic.spinLoopHint();
                        std.time.sleep(1 * std.time.ns_per_ms / 2);
                    }

                    if (std.c.dlclose(l) != 0)
                        @panic("System unstable: Error after library open and cannot close");
                    log.debug("closed old library. reloading executor at: {s}", .{executor.path});
                    executor.library = dlopen(executor.path) catch {
                        log.warn("could not reload! error opening library", .{});
                        return;
                    };
                    var symbol = std.c.dlsym(executor.library.?, SERVE_FN_NAME);
                    if (symbol == null) {
                        log.warn("could not reload! error finding symbol", .{});
                        if (std.c.dlclose(executor.library.?) != 0)
                            @panic("System unstable: Error after library open and cannot close");
                        return;
                    }
                    executor.serveFn = @ptrCast(symbol);
                    loadOptionalSymbols(executor);
                }
            }
        }
    }
}

/// Wrapper to the c library to make us more ziggy
fn dlopen(path: [:0]const u8) !*anyopaque {
    // We need now (and local) because we're about to call it
    const lib = std.c.dlopen(path, std.c.RTLD.NOW);
    if (lib) |l| return l;
    return error.CouldNotOpenDynamicLibrary;
}

/// Exits the application, which is wired up to SIGINT. This is the only
/// exit from the application as the main function has an infinite loop
fn exitApplication(
    _: i32,
    _: *const std.os.siginfo_t,
    _: ?*const anyopaque,
) callconv(.C) noreturn {
    exitApp(0);
    std.os.exit(0);
}

/// exitApp handles deinitialization for the application and any reporting
/// that needs to happen
fn exitApp(exitcode: u8) void {
    if (exitcode == 0)
        std.io.getStdOut().writer().print("termination request: stopping watch\n", .{}) catch {}
    else
        std.io.getStdErr().writer().print("abnormal termination: stopping watch\n", .{}) catch {};

    watcher.stopWatch() catch @panic("could not stop watcher");
    std.io.getStdOut().writer().print("exiting application\n", .{}) catch {};
    watcher.deinit();
    std.os.exit(exitcode);
    // joining threads will hang...we're ultimately in a signal handler.
    // But everything is shut down cleanly now, so I don't think it hurts to
    // just kill it all (NOTE: from a practical perspective, we do not seem
    // to get a clean shutdown in all cases)
    // if (watcher_thread) |t|
    //     t.join();
}

/// reloadConfig is wired to SIGHUP and will reload all executors. In its
/// current state, this is not a safe function as no connection draining
/// has been implemented. Operates off the main thread
fn reloadConfig(
    _: i32,
    _: *const std.os.siginfo_t,
    _: ?*const anyopaque,
) callconv(.C) void {
    // TODO: Gracefully drain in flight requests and hold a lock here while
    // we reload
    var allocator = std.heap.raw_c_allocator; // raw allocator recommended for use in arenas
    allocator.free(executors);
    parsed_config.deinit();
    executors = loadConfig(allocator) catch {
        // TODO: Need to refactor so loadConfig brings back a struct with
        // executors and parsed_config, then we can manage the lifecycle better
        // and avoid this @panic call for more graceful handling
        @panic("Could not reload config");
    };
}

/// Installs all signal handlers for shutdown and configuration reload
fn installSignalHandler() !void {
    var act = std.os.Sigaction{
        .handler = .{ .sigaction = exitApplication },
        .mask = std.os.empty_sigset,
        .flags = (std.os.SA.SIGINFO | std.os.SA.RESTART | std.os.SA.RESETHAND),
    };

    try std.os.sigaction(std.os.SIG.INT, &act, null);
    try std.os.sigaction(std.os.SIG.TERM, &act, null);

    var hup_act = std.os.Sigaction{
        .handler = .{ .sigaction = reloadConfig },
        .mask = std.os.empty_sigset,
        .flags = (std.os.SA.SIGINFO | std.os.SA.RESTART | std.os.SA.RESETHAND),
    };
    try std.os.sigaction(std.os.SIG.HUP, &hup_act, null);
}

pub fn main() !void {
    defer exitApp(1);

    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    // const stdout_file = std.io.getStdOut().writer();
    // var bw = std.io.bufferedWriter(stdout_file);
    // const stdout = bw.writer();

    var allocator = std.heap.raw_c_allocator; // raw allocator recommended for use in arenas
    executors = try loadConfig(allocator);
    defer allocator.free(executors);
    defer parsed_config.deinit();

    watcher_thread = try std.Thread.spawn(.{}, Watch.startWatch, .{&watcher});

    var server = std.http.Server.init(allocator, .{ .reuse_address = true });
    defer server.deinit();

    const address = try std.net.Address.parseIp(
        "0.0.0.0",
        if (std.os.getenv("PORT")) |p| try std.fmt.parseInt(u16, p, 10) else PORT,
    );
    try server.listen(address);
    const server_port = server.socket.listen_address.in.getPort();
    log.info("listening on port: {d}", .{server_port});
    if (builtin.os.tag == .linux)
        log.info("pid: {d}", .{std.os.linux.getpid()});

    try installSignalHandler();
    response_preallocation_kb = if (std.os.getenv("RESPONSE_PREALLOCATION_KB")) |kb|
        try std.fmt.parseInt(usize, kb, 10)
    else
        response_preallocation_kb;
    var server_thread_count = if (std.os.getenv("SERVER_THREAD_COUNT")) |count|
        try std.fmt.parseInt(usize, count, 10)
    else switch (builtin.mode) {
        .Debug => @min(4, try std.Thread.getCpuCount()),
        else => try std.Thread.getCpuCount(),
    };
    switch (builtin.mode) {
        .Debug => log.info("serving using {d} threads (debug build: capped at 4)", .{server_thread_count}),
        else => log.info("serving using {d} threads", .{server_thread_count}),
    }
    var server_threads = try std.ArrayList(std.Thread).initCapacity(allocator, server_thread_count);
    defer server_threads.deinit();
    // Set up thread pool
    for (0..server_thread_count) |inx| {
        server_threads.appendAssumeCapacity(try std.Thread.spawn(
            .{},
            threadMain,
            .{ allocator, &server, inx },
        ));
    }
    // main thread will no longer do anything
    std.time.sleep(std.math.maxInt(u64));
    for (server_threads.items) |thread| thread.join();
}

fn threadMain(allocator: std.mem.Allocator, server: *std.http.Server, thread_number: usize) !void {
    // TODO: If we're in a thread pool we need to be careful with this...
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    log.info("starting server thread {d}, tid {d}", .{ thread_number, std.Thread.getCurrentId() });
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var aa = arena.allocator();
    const bytes_preallocated = try preWarmArena(aa, &arena, response_preallocation_kb);
    while (true) {
        defer {
            if (!arena.reset(.{ .retain_capacity = {} })) {
                // reallocation failed, arena is degraded
                log.warn("Arena reset failed and is degraded. Resetting arena", .{});
                arena.deinit();
                arena = std.heap.ArenaAllocator.init(allocator);
                aa = arena.allocator();
            }
        }

        processRequest(&aa, server, stdout) catch |e| {
            log.err("Unexpected error processing request: {any}", .{e});
            if (@errorReturnTrace()) |trace| {
                std.debug.dumpStackTrace(trace.*);
            }
        };
        try stdout.print(" (pre-alloc: {}, alloc: {})\n", .{ bytes_preallocated, arena.queryCapacity() });
        try bw.flush();
    }
}

fn loadConfig(allocator: std.mem.Allocator) ![]Executor {
    log.info("loading config", .{});
    // We will not watch this file - let it reload on SIGHUP
    var config_file = try std.fs.cwd().openFile("proxy.ini", .{});
    defer config_file.close();
    parsed_config = try config.init(allocator).parse(config_file.reader());
    var al = try std.ArrayList(Executor).initCapacity(allocator, parsed_config.key_value_map.keys().len);
    defer al.deinit();
    for (parsed_config.key_value_map.keys(), parsed_config.key_value_map.values()) |k, v| {
        al.appendAssumeCapacity(.{
            .match_data = k,
            .path = v,
        });
    }
    log.info("config loaded", .{});
    return al.toOwnedSlice(); // TODO: This should return a struct with the parsed config and executors
}

/// main loop calls processRequest, which is responsible for the interface
/// with logs, connection accounting, etc. The work dealing with the request
/// itself is delegated to the serve function to work with the executor
fn processRequest(allocator: *std.mem.Allocator, server: *std.http.Server, writer: anytype) !void {
    if (timer == null) timer = try std.time.Timer.start();
    var tm = timer.?;
    var res = try server.accept(.{ .allocator = allocator.* });
    defer res.deinit();
    defer _ = res.reset();
    try res.wait(); // wait for client to send a complete request head
    // I believe it's fair to start our timer after this is done
    tm.reset();

    // This is an nginx log:
    // git.lerch.org 50.39.111.175 - - [16/May/2023:02:56:31 +0000] "POST /api/actions/runner.v1.RunnerService/FetchTask HTTP/2.0" 200 0 "-" "connect-go/1.2.0-dev (go1.20.1)" "172.20.0.5:3000"
    // TODO: replicate this
    try writer.print("{} - - \"{s} {s} {s}\"", .{
        res.address,
        @tagName(res.request.method),
        res.request.target,
        @tagName(res.request.version),
    });
    const errstr = "Internal Server Error\n";
    var errbuf: [errstr.len]u8 = undefined;
    var response_bytes = try std.fmt.bufPrint(&errbuf, errstr, .{});

    var full_response = serve(allocator, &res) catch |e| brk: {
        res.status = .internal_server_error;
        // TODO: more about this particular request
        log.err("Unexpected error from executor processing request: {any}", .{e});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
        break :brk null;
    };
    defer {
        // The call above converts uncaught errors to a null
        // In request counter gets incremented during getExecutor
        // Caught errors will get our in_flight counter decremented (see serve fn)
        //   - we cannot do this here because we may not have an executor at all
        // This leaves this defer block as the only place we can/should decrement
        // under normal conditions

        if (full_response) |f| {
            if (f.executor.requestDeinitFn) |d| d();
            _ = f.executor.requests_in_flight.fetchSub(1, .Release);
        }
    }
    if (full_response) |f|
        response_bytes = f.response;
    res.transfer_encoding = .{ .content_length = response_bytes.len };
    try res.headers.append("connection", "close");
    try writer.print(" {d} ttfb {d:.3}ms", .{ @intFromEnum(res.status), @as(f64, @floatFromInt(tm.read())) / std.time.ns_per_ms });
    if (builtin.is_test) writeToTestBuffers(response_bytes, &res);
    try res.do();
    _ = try res.writer().writeAll(response_bytes);
    try res.finish();
    try writer.print(" {d} ttlb {d:.3}ms", .{
        response_bytes.len,
        @as(f64, @floatFromInt(tm.read())) / std.time.ns_per_ms,
    });
}

fn toHeaders(allocator: std.mem.Allocator, headers: std.http.Headers) ![*]interface.Header {
    var header_array = try std.ArrayList(interface.Header).initCapacity(allocator, headers.list.items.len);
    for (headers.list.items) |kv| {
        header_array.appendAssumeCapacity(.{
            .name_ptr = @constCast(kv.name).ptr,
            .name_len = kv.name.len,

            .value_ptr = @constCast(kv.value).ptr,
            .value_len = kv.value.len,
        });
    }
    return header_array.items.ptr;
}

/// Allocates at least preallocated_kb kilobytes of ram for usage. Some overhead
/// will mean that more
fn preWarmArena(aa: std.mem.Allocator, arena: *std.heap.ArenaAllocator, preallocated_kb: usize) !usize {
    if (preallocated_kb == 0) return 0;
    // capacity 0 at this point
    const warm_array = try aa.alloc(u8, 1024 * preallocated_kb); // after this, we are at 1569 (545 extra)
    aa.free(warm_array);
    log.debug(
        "allocator preallocation. Limiting to: {d} bytes",
        .{(arena.queryCapacity() + @as(usize, 1023)) / @as(usize, 1024) * 1024},
    );
    if (!arena.reset(.{ .retain_with_limit = (arena.queryCapacity() + @as(usize, 1023)) / @as(usize, 1024) * 1024 }))
        log.warn("arena reset failed, arena degraded", .{});
    var bytes_allocated = arena.queryCapacity();
    log.debug("preallocated {d} bytes", .{bytes_allocated});
    return bytes_allocated;
}
fn writeToTestBuffers(response: []const u8, res: *std.http.Server.Response) void {
    _ = res;
    log.debug("writing to test buffers", .{});
    // This performs core dump...because we're in a separate thread?
    // @memset(test_resp_buf, 0);
    const errmsg = "response exceeds 1024 bytes";
    const src = if (response.len < 1024) response else errmsg;
    test_resp_buf_len = if (response.len < 1024) response.len else errmsg.len;
    for (src, 0..) |b, i| test_resp_buf[i] = b;
    for (test_resp_buf_len..1024) |i| test_resp_buf[i] = 0;
}
fn testRequest(request_bytes: []const u8) !void {
    const allocator = std.testing.allocator;
    executors = try loadConfig(allocator);
    defer allocator.free(executors);
    defer parsed_config.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var server = std.http.Server.init(allocator, .{ .reuse_address = true });
    defer server.deinit();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    try server.listen(address);
    const server_port = server.socket.listen_address.in.getPort();

    var al = std.ArrayList(u8).init(allocator);
    defer al.deinit();
    var writer = al.writer();
    var aa = arena.allocator();
    var bytes_allocated: usize = 0;
    // pre-warm
    bytes_allocated = try preWarmArena(aa, &arena, response_preallocation_kb);
    const server_thread = try std.Thread.spawn(
        .{},
        processRequest,
        .{ &aa, &server, writer },
    );

    const stream = try std.net.tcpConnectToHost(allocator, "127.0.0.1", server_port);
    defer stream.close();
    _ = try stream.writeAll(request_bytes[0..]);

    server_thread.join();
    log.debug("Bytes allocated during request: {d}", .{arena.queryCapacity() - bytes_allocated});
    log.debug("Stdout: {s}", .{al.items});
}

fn testGet(comptime path: []const u8) !void {
    try testRequest("GET " ++ path ++ " HTTP/1.1\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n");
}

fn testHostGet(comptime host: []const u8, comptime path: []const u8) !void {
    try testRequest("GET " ++ path ++ " HTTP/1.1\r\n" ++
        "Host: " ++ host ++ "\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n");
}

test {
    // To run nested container tests, either, call `refAllDecls` which will
    // reference all declarations located in the given argument.
    // `@This()` is a builtin function that returns the innermost container it is called from.
    // In this example, the innermost container is this file (implicitly a struct).
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(config);
    std.testing.refAllDecls(interface);
}
var test_resp_buf: [1024]u8 = undefined;
var test_resp_buf_len: usize = undefined;
test "root path get" {
    std.testing.log_level = .debug;
    log.debug("", .{});
    try testGet("/");
    try std.testing.expectEqual(@as(usize, 2), test_resp_buf_len);
    try std.testing.expectEqualStrings(" 1", test_resp_buf[0..test_resp_buf_len]);
}
test "root path, alternative host get" {
    std.testing.log_level = .debug;
    log.debug("", .{});
    try testHostGet("iam.aws.lerch.org", "/");
    try std.testing.expectEqualStrings("iam response", test_resp_buf[0..test_resp_buf_len]);
}
