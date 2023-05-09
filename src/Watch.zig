const builtin = @import("builtin");
const std = @import("std");
const c = @cImport({
    @cInclude("poll.h");
});

const MAX_FDS = 1024;

const Self = @This();

fileChanged: *const fn (usize) void,
inotify_fd: ?std.os.fd_t = null,
// sizeof(std.os.pollfd) == 8, so this is 8k
// fds: [MAX_FDS]std.os.pollfd = [_]std.os.pollfd{.{ .fd = 0, .events = 0, .revents = 0 }} ** MAX_FDS,
nfds_t: usize = 0,
wds: [MAX_FDS]i32 = [_]i32{0} ** MAX_FDS,
modified: [MAX_FDS]bool = [_]bool{false} ** MAX_FDS,

pub fn init(file_changed: *const fn (usize) void) Self {
    if (builtin.os.tag != .linux)
        @compileError("Unsupported OS");
    return .{
        .fileChanged = file_changed,
    };
}

pub fn deinit(self: *Self) void {
    if (self.inotify_fd) |fd| {
        for (self.wds) |wd| {
            const rc = std.os.linux.inotify_rm_watch(fd, wd);
            // Errno can only be EBADF, EINVAL if either the inotify fs or the wd are invalid
            std.debug.assert(rc == 0);
        }
        std.os.close(fd);
    }
}

pub fn watchFds(self: *Self) void {
    while (true) {
        if (self.nfds_t == 0) {
            std.time.sleep(250);
            continue;
        }
        var fds = &[_]std.os.pollfd{.{ .fd = self.inotify_fd.?, .events = c.POLLIN, .revents = 0 }};
        // NOTE: There is a std.io.poll that provides a higher level abstraction.
        // However, this API is strictly related to the use case of an open stream
        // for which we are awaiting data. In this case, we are polling for
        // an inotify event, for which no abstraction currently exists
        //
        // std.fs.watch looks really good...but it requires event based I/O,
        // which is not yet ready to be (re)added.
        if ((std.os.poll(
            fds,
            -1, // Infinite timeout
        ) catch @panic("poll error")) > 0) {
            if (fds[0].revents & c.POLLIN == c.POLLIN) { // POLLIN means "there is data to read"
                var event_buf: [4096]u8 align(@alignOf(std.os.linux.inotify_event)) = undefined;
                // "borrowed" from https://ziglang.org/documentation/master/std/src/std/fs/watch.zig.html#L588
                const bytes_read = std.os.read(self.inotify_fd.?, &event_buf) catch unreachable;

                var ptr: [*]u8 = &event_buf;
                const end_ptr = ptr + bytes_read;
                while (@ptrToInt(ptr) < @ptrToInt(end_ptr)) {
                    const ev = @ptrCast(
                        *const std.os.linux.inotify_event,
                        @alignCast(@alignOf(*const std.os.linux.inotify_event), ptr),
                    );

                    if (ev.mask & std.os.linux.IN.MODIFY == std.os.linux.IN.MODIFY) {
                        for (self.wds, 0..) |wd, inx| {
                            if (ev.wd == wd)
                                self.modified[inx] = true;
                        }
                    }
                    // attrib added as build process moves in place and modifies attributes
                    // TODO: Also watch MOVED_TO, which is on the directory...
                    if (ev.mask & std.os.linux.IN.CLOSE_WRITE == std.os.linux.IN.CLOSE_WRITE or
                        ev.mask & std.os.linux.IN.ATTRIB == std.os.linux.IN.ATTRIB)
                    {
                        for (self.wds, 0..) |wd, inx| {
                            if (ev.wd == wd)
                                self.fileChanged(inx);
                        }
                    }
                    if (ev.mask & std.os.linux.IN.CLOSE_NOWRITE == std.os.linux.IN.CLOSE_NOWRITE) {
                        for (self.wds, 0..) |wd, inx| {
                            if (ev.wd == wd and self.modified[inx]) {
                                self.modified[inx] = false;
                                self.fileChanged(inx);
                            }
                        }
                    }
                    // see man 2 poll
                    self.handleFile(fds[0]);
                    ptr = @alignCast(
                        @alignOf(std.os.linux.inotify_event),
                        ptr + @sizeOf(std.os.linux.inotify_event) + ev.len,
                    );
                }
            }
        }
    }
}

pub fn addFileWatch(self: *Self, path: [:0]const u8) !usize {
    self.inotify_fd = self.inotify_fd orelse try std.os.inotify_init1(std.os.linux.IN.NONBLOCK);
    errdefer {
        std.os.close(self.inotify_fd.?);
        self.inotify_fd = null;
    }
    // open 20, close_norite 10, attrib 4
    self.wds[self.nfds_t] = try std.os.inotify_add_watchZ(
        self.inotify_fd.?,
        path,
        std.os.linux.IN.ATTRIB | std.os.linux.IN.CLOSE | std.os.linux.IN.CLOSE_WRITE | std.os.linux.IN.MODIFY,
    );
    if (self.wds[self.nfds_t] == -1)
        @panic("could not set watch");
    self.nfds_t += 1;
    return self.nfds_t - 1;
}

fn handleFile(self: Self, fd: std.os.pollfd) void {
    _ = fd;
    _ = self;
}
