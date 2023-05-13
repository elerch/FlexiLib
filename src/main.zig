const std = @import("std");
const builtin = @import("builtin");
const interface = @import("interface.zig");
const Watch = @import("Watch.zig");
const serveFn = *const fn () ?*interface.Response;
const requestDeinitFn = *const fn () void;

const timeout = 250;

const FullReturn = struct {
    response: []u8,
    executor: *Executor,
};

const Executor = struct {
    // configuration
    path: [:0]const u8,

    // fields used at runtime to do real work
    library: ?*anyopaque = null,
    serveFn: ?serveFn = null,
    requestDeinitFn: ?requestDeinitFn = null,

    // fields used for internal accounting
    watch: ?usize = null,
    reload_lock: bool = false,
    in_request_lock: bool = false,
};

// TODO: This should be in a file that maybe gets reloaded with SIGHUP
// rather than a file watch. Touching this config is pretty dangerous
var executors = [_]Executor{
    .{ .path = "zig-out/lib/libfaas-proxy-sample-lib.so" },
    .{ .path = "zig-out/lib/libfaas-proxy-sample-lib2.so" },
};

var watcher = Watch.init(executorChanged);
var watcher_thread: ?std.Thread = null;

const log = std.log.scoped(.main);
pub const std_options = struct {
    pub const log_level = .debug;

    pub const log_scope_levels = &[_]std.log.ScopeLevel{
        .{ .scope = .watch, .level = .info },
    };
};
const SERVE_FN_NAME = "handle_request";
const PORT = 8069;

fn serve(allocator: std.mem.Allocator, response: *std.http.Server.Response) !*FullReturn {
    // pub const Request = extern struct {
    //     method: [*]u8,
    //     method_len: usize,
    //
    //     content: [*]u8,
    //     content_len: usize,
    //
    //     headers: [*]Header,
    //     headers_len: usize,
    // };
    // if (some path routing thing) {
    // TODO: Get request body into executor
    // TODO: Get headers back from executor
    // TODO: Get request headers into executor
    const executor = try getExecutor(0);
    executor.in_request_lock = true;
    errdefer executor.in_request_lock = false;
    // Call external library
    var serve_result = executor.serveFn.?().?; // ok for this pointer deref to fail

    // Deal with results
    // var content_type_added = false;
    // for (0..serve_result.headers_len) |inx| {
    //     const head = serve_result.headers[inx];
    //     try response.headers.append(
    //         head.name_ptr[0..head.name_len],
    //         head.value_ptr[0..head.value_len],
    //     );
    //
    //     // TODO: are these headers case insensitive?
    //     content_type_added = std.mem.eql(u8, head.name_ptr[0..head.name_len], "content-type");
    // }
    // if (!content_type_added)
    //     try response.headers.append("content-type", "text/plain");
    _ = response;
    var slice: []u8 = serve_result.ptr[0..serve_result.len];
    var rc = try allocator.create(FullReturn);
    rc.executor = executor;
    rc.response = slice;
    return rc;
}
fn getExecutor(key: usize) !*Executor {
    var executor = &executors[key];
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
}
fn executorChanged(watch: usize) void {
    // NOTE: This will be called off the main thread
    log.debug("executor with watch {d} changed", .{watch});
    for (&executors) |*executor| {
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
fn installSignalHandler() !void {
    var act = std.os.Sigaction{
        .handler = .{ .sigaction = exitApplication },
        .mask = std.os.empty_sigset,
        .flags = (std.os.SA.SIGINFO | std.os.SA.RESTART | std.os.SA.RESETHAND),
    };

    try std.os.sigaction(std.os.SIG.INT, &act, null);
    try std.os.sigaction(std.os.SIG.TERM, &act, null);
}

pub fn main() !void {
    defer exitApp(1);

    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    const stderr_file = std.io.getStdErr().writer();
    var bw_stderr = std.io.bufferedWriter(stderr_file);
    const stderr = bw_stderr.writer();
    _ = stderr;

    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    try bw.flush(); // don't forget to flush!
    watcher_thread = try std.Thread.spawn(.{}, Watch.startWatch, .{&watcher});

    var allocator = std.heap.raw_c_allocator; // raw allocator recommended for use in arenas
    var server = std.http.Server.init(allocator, .{ .reuse_address = true });
    defer server.deinit();

    const address = try std.net.Address.parseIp("0.0.0.0", PORT);
    try server.listen(address);
    const server_port = server.socket.listen_address.in.getPort();
    log.info("listening on port: {d}", .{server_port});
    if (builtin.os.tag == .linux)
        log.info("pid: {d}", .{std.os.linux.getpid()});

    try installSignalHandler();
    while (true) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        processRequest(arena.allocator(), &server) catch |e| {
            log.err("Unexpected error processing request: {any}", .{e});
            if (@errorReturnTrace()) |trace| {
                std.debug.dumpStackTrace(trace.*);
            }
        };
    }
}

fn processRequest(allocator: std.mem.Allocator, server: *std.http.Server) !void {
    const max_header_size = 8192;
    const res = try server.accept(.{ .dynamic = max_header_size });
    defer res.deinit();
    defer res.reset();
    try res.wait();

    // TODO: deal with this
    var buf: [1024]u8 = undefined;
    const n = try res.readAll(&buf);
    _ = n;

    // TODO: we need to also have a defer statement to deinit whatever happens
    // with the executor library. This will also add a race condition where
    // we could have a memory leak if the executor reloads in the middle of a
    // request. We may want to add a new spinlock on the reload thread to
    // avoid reloading in the middle of a request, which would be generally
    // bad anyway
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
    if (builtin.is_test) writeToTestBuffers(response_bytes, res);
    try res.do();
    _ = try res.writer().writeAll(response_bytes);
    try res.finish();
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
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var server = std.http.Server.init(allocator, .{ .reuse_address = true });
    defer server.deinit();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    try server.listen(address);
    const server_port = server.socket.listen_address.in.getPort();

    const server_thread = try std.Thread.spawn(
        .{},
        processRequest,
        .{ arena.allocator(), &server },
    );

    const stream = try std.net.tcpConnectToHost(allocator, "127.0.0.1", server_port);
    defer stream.close();
    _ = try stream.writeAll(request_bytes[0..]);

    server_thread.join();
}

fn testGet(comptime path: []const u8) !void {
    try testRequest("GET " ++ path ++ " HTTP/1.1\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n");
}

test {
    // To run nested container tests, either, call `refAllDecls` which will
    // reference all declarations located in the given argument.
    // `@This()` is a builtin function that returns the innermost container it is called from.
    // In this example, the innermost container is this file (implicitly a struct).
    std.testing.refAllDecls(@This());
}
var test_resp_buf: [1024]u8 = undefined;
var test_resp_buf_len: usize = undefined;
test "root path get" {
    // std.testing.log_level = .debug;
    try testGet("/");
    try std.testing.expectEqual(@as(usize, 3), test_resp_buf_len);
    try std.testing.expectEqualStrings(" 2.", test_resp_buf[0..test_resp_buf_len]);
}
