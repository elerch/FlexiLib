const std = @import("std");

const Watch = @import("Watch.zig");
const serveFn = *const fn () void;

var shutdown = false;
const timeout = 250;

const Executor = struct {
    path: [:0]const u8,
    library: ?*anyopaque = null,
    serveFn: ?serveFn = null,
    watch: ?usize = null,
    reload_lock: bool = false,
};

var executors = [_]Executor{
    .{ .path = "zig-out/lib/libfaas-proxy-sample-lib.so" },
    .{ .path = "zig-out/lib/libfaas-proxy-sample-lib2.so" },
};

var watcher = Watch.init(executorChanged);
const log = std.log.scoped(.main);
pub const std_options = struct {
    pub const log_level = .debug;

    pub const log_scope_levels = &[_]std.log.ScopeLevel{
        .{ .scope = .watch, .level = .info },
    };
};
const SERVE_FN_NAME = "serve";

fn serve() !void {
    // if (some path routing thing) {

    (try getExecutor(0))();
    // if (inx > 4) {
    //     if (inx % 2 == 0)
    //         (try getExecutor(0))()
    //     else
    //         (try getExecutor(1))();
    // }
}
fn getExecutor(key: usize) !serveFn {
    var executor = &executors[key];
    if (executor.serveFn) |s| return s;

    executor.library = blk: {
        if (executor.library) |l|
            break :blk l;

        while (executor.reload_lock) // system is reloading the library
            std.time.sleep(1);

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
    return executor.serveFn.?;
}

fn executorChanged(watch: usize) void {
    // NOTE: This will be called off the main thread
    log.debug("executor with watch {d} changed", .{watch});
    for (&executors) |*executor| {
        if (executor.watch) |w| {
            if (w == watch) {
                if (executor.library) |l| {
                    executor.reload_lock = true;
                    defer executor.reload_lock = false;

                    if (std.c.dlclose(l) != 0)
                        @panic("System unstable: Error after library open and cannot close");
                    log.debug("closed old library. reloading executor at: {s}", .{executor.path});
                    executor.library = dlopen(executor.path) catch {
                        log.warn("could not reload! error opening library", .{});
                        return;
                    };
                    executor.serveFn = @ptrCast(serveFn, std.c.dlsym(executor.library.?, SERVE_FN_NAME));
                    if (executor.serveFn == null) {
                        log.warn("could not reload! error finding symbol", .{});
                        if (std.c.dlclose(executor.library.?) != 0)
                            @panic("System unstable: Error after library open and cannot close");
                        return;
                    }
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

var inx: usize = 0;
pub fn main() !void {
    defer watcher.deinit();

    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    const stderr_file = std.io.getStdErr().writer();
    var bw_stderr = std.io.bufferedWriter(stderr_file);
    const stderr = bw_stderr.writer();

    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    try bw.flush(); // don't forget to flush!
    const watcher_thread = try std.Thread.spawn(.{}, Watch.startWatch, .{&watcher});

    while (true) {
        std.time.sleep(std.time.ns_per_s * 2);
        inx += 1;
        if (inx == 10) {
            log.debug("forcing stop to make sure it works", .{});
            try watcher.stopWatch();
            break;
        }
        try stdout.print("Serving...", .{});
        try bw.flush();
        serve() catch |err| {
            try stderr.print("Error serving request ({any})\n", .{err});
            try bw_stderr.flush();
        };
        try stdout.print("served\n", .{});
        try bw.flush();
    }
    shutdown = true;
    watcher_thread.join();
}
test {
    // To run nested container tests, either, call `refAllDecls` which will
    // reference all declarations located in the given argument.
    // `@This()` is a builtin function that returns the innermost container it is called from.
    // In this example, the innermost container is this file (implicitly a struct).
    std.testing.refAllDecls(@This());
}
test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
