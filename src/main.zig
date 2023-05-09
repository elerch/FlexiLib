const std = @import("std");
const c = @cImport({
    @cInclude("dlfcn.h");
});

const Watch = @import("Watch.zig");
const serve_op = *const fn () void;

var shutdown = false;
const timeout = 250;

const Executor = struct {
    path: [:0]const u8,
    library: ?*anyopaque = null,
    serve: ?serve_op = null,
    watch: ?usize = null,
};

var executors = [_]Executor{.{
    .path = "/home/lobo/home/faas-proxy/zig-out/lib/libfaas-proxy-sample-lib.so",
}};

var watcher = Watch.init(executorChanged);

fn serve() !void {
    // if (some path routing thing) {

    (try getExecutor(0))();
    // if (std.c.dlerror()) |_| { // TODO: use capture
    //     return error.CouldNotLoadSymbolServe;
    // }
    // TODO: only close on reload
    // if (std.c.dlclose(library.?) != 0) {
    //     return error.CouldNotUnloadLibrary;
    // }
    // library = null;
    // }
}
fn getExecutor(key: usize) !serve_op {
    var executor = &executors[key];
    if (executor.serve) |s| return s;

    executor.library = blk: {
        if (executor.library) |l| {
            break :blk l;
        }
        const l = try dlopen(executor.path);
        errdefer if (std.c.dlclose(l) != 0)
            @panic("System unstable: Error after library open and cannot close");
        executor.watch = try watcher.addFileWatch(executor.path);
        break :blk l;
    };

    // std.c.dlerror();
    const serve_function = std.c.dlsym(executor.library.?, "serve");
    if (serve_function == null) return error.CouldNotLoadSymbolServe;

    executor.serve = @ptrCast(serve_op, serve_function.?);
    return executor.serve.?;
}

// This works
fn executorChanged(watch: usize) void {
    for (&executors) |*executor| {
        if (executor.watch) |w| {
            if (w == watch) {
                if (executor.library) |l| {
                    // TODO: These two lines could introduce a race. Right now that would mean a panic
                    executor.serve = null;
                    if (std.c.dlclose(l) != 0)
                        @panic("System unstable: Error after library open and cannot close");
                }
                executor.library = null;
                executor.serve = null;
            }
        }
    }
}

// NOTE: this will be on a different thread. This code does not work, and I
// am fairly certain it is because we can't share a function pointer between
// threads
// fn executorChanged(watch: usize) void {
//     std.debug.print("executor with watch {d} changed\n", .{watch});
//     for (&executors) |*executor| {
//         if (executor.watch) |w| {
//             if (w == watch) {
//                 if (executor.library) |l| {
//                     std.debug.print("reloading executor at path: {s}\n", .{executor.path});
//                     const newlib = dlopen(executor.path) catch {
//                         std.debug.print("could not reload! error opening library\n", .{});
//                         return;
//                     };
//                     errdefer if (std.c.dlclose(newlib) != 0)
//                         @panic("System unstable: Error after library open and cannot close");
//                     const serve_function = std.c.dlsym(newlib, "serve");
//                     if (serve_function == null) {
//                         std.debug.print("could not reload! error finding symbol\n", .{});
//                         return;
//                     }
//                     // new lib all loaded up - do the swap and close the old
//                     std.debug.print("updating function and library\n", .{});
//                     executor.serve = @ptrCast(serve_op, serve_function.?);
//                     executor.library = newlib;
//                     if (std.c.dlclose(l) != 0)
//                         @panic("System unstable: Error after library open and cannot close");
//                     std.debug.print("closed old library\n", .{});
//                 }
//             }
//         }
//     }
// }

fn dlopen(path: [:0]const u8) !*anyopaque {
    // We need now (and local) because we're about to call it
    const lib = std.c.dlopen(path, c.RTLD_NOW);
    if (lib) |l| return l;
    return error.CouldNotOpenDynamicLibrary;
}

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

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
