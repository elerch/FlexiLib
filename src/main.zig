const std = @import("std");
const builtin = @import("builtin");
const interface = @import("interface.zig");
const Watch = @import("Watch.zig");
const config = @import("config.zig");

const serveFn = *const fn (*interface.Request) ?*interface.Response;
const zigInitFn = *const fn (*anyopaque) void;
const requestDeinitFn = *const fn () void;
const timeout = 250;

const FullReturn = struct {
    response: []u8,
    executor: *Executor,
};

const Executor = struct {
    // configuration
    target_prefix: []const u8,
    path: [:0]const u8,

    // fields used at runtime to do real work
    library: ?*anyopaque = null,
    serveFn: ?serveFn = null,
    zigInitFn: ?zigInitFn = null,
    requestDeinitFn: ?requestDeinitFn = null,

    // fields used for internal accounting
    watch: ?usize = null,
    reload_lock: bool = false,
    in_request_lock: bool = false,
};

var watcher = Watch.init(executorChanged);
var watcher_thread: ?std.Thread = null;
var timer: ?std.time.Timer = null; // timer used by processRequest

const log = std.log.scoped(.main);
pub const std_options = struct {
    pub const log_level = .debug;

    pub const log_scope_levels = &[_]std.log.ScopeLevel{
        .{ .scope = .watch, .level = .info },
    };
};
const SERVE_FN_NAME = "handle_request";
const PORT = 8069;

var executors: []Executor = undefined;

fn serve(allocator: *std.mem.Allocator, response: *std.http.Server.Response) !*FullReturn {
    // if (some path routing thing) {
    const executor = try getExecutor(response.request.target);
    if (executor.zigInitFn) |f|
        f(allocator);

    executor.in_request_lock = true;
    errdefer executor.in_request_lock = false;
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
    log.warn("response ptr: {*}", .{serve_result.ptr}); // BUG: This works in tests, but does not when compiled (even debug mode)
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
fn getExecutor(requested_path: []const u8) !*Executor {
    var executor = blk: {
        for (executors) |*exec| {
            if (std.mem.startsWith(u8, requested_path, exec.target_prefix)) {
                break :blk exec;
            }
        }
        log.err("Could not find executor for target path '{s}'", .{requested_path});
        return error.NoApplicableExecutor;
    };
    if (executor.serveFn != null) return executor;

    executor.library = blk: {
        if (executor.library) |l|
            break :blk l;

        while (executor.reload_lock) // system is reloading the library
            std.time.sleep(1 * std.time.ns_per_ms / 2);

        if (executor.library) |l| // check again to see where we are at
            break :blk l;

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

    executor.serveFn = @ptrCast(serveFn, serve_fn.?);
    loadOptionalSymbols(executor);
    return executor;
}

fn loadOptionalSymbols(executor: *Executor) void {
    if (std.c.dlsym(executor.library.?, "request_deinit")) |s| {
        executor.requestDeinitFn = @ptrCast(requestDeinitFn, s);
    }
    if (std.c.dlsym(executor.library.?, "zigInit")) |s| {
        executor.zigInitFn = @ptrCast(zigInitFn, s);
    }
}
fn executorChanged(watch: usize) void {
    // NOTE: This will be called off the main thread
    log.debug("executor with watch {d} changed", .{watch});
    for (executors) |*executor| {
        if (executor.watch) |w| {
            if (w == watch) {
                if (executor.library) |l| {
                    while (executor.in_request_lock)
                        std.time.sleep(1 * std.time.ns_per_ms / 2);
                    executor.reload_lock = true;
                    defer executor.reload_lock = false;

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
                    executor.serveFn = @ptrCast(serveFn, symbol);
                    loadOptionalSymbols(executor);
                }
            }
        }
    }
}

fn dlopen(path: [:0]const u8) !*anyopaque {
    // We need now (and local) because we're about to call it
    const lib = std.c.dlopen(path, std.c.RTLD.NOW);
    if (lib) |l| return l;
    return error.CouldNotOpenDynamicLibrary;
}

// fn exitApplication(sig: i32, info: *const std.os.siginfo_t, ctx_ptr: ?*const anyopaque,) callconv(.C) noreturn {
fn exitApplication(
    _: i32,
    _: *const std.os.siginfo_t,
    _: ?*const anyopaque,
) callconv(.C) noreturn {
    exitApp(0);
    std.os.exit(0);
}

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
    // just kill it all
    // if (watcher_thread) |t|
    //     t.join();
}
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
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    var allocator = std.heap.raw_c_allocator; // raw allocator recommended for use in arenas
    executors = try loadConfig(allocator);
    defer allocator.free(executors);
    defer parsed_config.deinit();

    watcher_thread = try std.Thread.spawn(.{}, Watch.startWatch, .{&watcher});

    var server = std.http.Server.init(allocator, .{ .reuse_address = true });
    defer server.deinit();

    const address = try std.net.Address.parseIp("0.0.0.0", PORT);
    try server.listen(address);
    const server_port = server.socket.listen_address.in.getPort();
    log.info("listening on port: {d}", .{server_port});
    if (builtin.os.tag == .linux)
        log.info("pid: {d}", .{std.os.linux.getpid()});

    try installSignalHandler();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var aa = arena.allocator();
    const bytes_preallocated = try preWarmArena(aa, &arena, 1);
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

        processRequest(&aa, &server, stdout) catch |e| {
            log.err("Unexpected error processing request: {any}", .{e});
            if (@errorReturnTrace()) |trace| {
                std.debug.dumpStackTrace(trace.*);
            }
        };
        try stdout.print(" (pre-alloc: {}, alloc: {})\n", .{ bytes_preallocated, arena.queryCapacity() });
        try bw.flush();
    }
}
var parsed_config: config.ParsedConfig = undefined;
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
            .target_prefix = k,
            .path = v,
        });
    }
    log.info("config loaded", .{});
    return al.toOwnedSlice();
}

fn processRequest(allocator: *std.mem.Allocator, server: *std.http.Server, writer: anytype) !void {
    const max_header_size = 8192;
    if (timer == null) timer = try std.time.Timer.start();
    var tm = timer.?;
    const res = try server.accept(.{ .dynamic = max_header_size });
    defer res.deinit();
    defer res.reset();
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

    var full_response = serve(allocator, res) catch |e| brk: {
        res.status = .internal_server_error;
        // TODO: more about this particular request
        log.err("Unexpected error from executor processing request: {any}", .{e});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
        break :brk null;
    };
    defer {
        if (full_response) |f| {
            if (f.executor.requestDeinitFn) |d| d();
            f.executor.in_request_lock = false;
        }
    }
    if (full_response) |f|
        response_bytes = f.response;
    res.transfer_encoding = .{ .content_length = response_bytes.len };
    try res.headers.append("connection", "close");
    try writer.print(" {d} ttfb {d:.3}ms", .{ @enumToInt(res.status), @intToFloat(f64, tm.read()) / std.time.ns_per_ms });
    if (builtin.is_test) writeToTestBuffers(response_bytes, res);
    try res.do();
    _ = try res.writer().writeAll(response_bytes);
    try res.finish();
    try writer.print(" {d} ttlb {d:.3}ms", .{
        response_bytes.len,
        @intToFloat(f64, tm.read()) / std.time.ns_per_ms,
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
    for (src, 0..) |b, i| {
        test_resp_buf[i] = b;
    }
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
    bytes_allocated = try preWarmArena(aa, &arena, 1);
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
