const builtin = @import("builtin");
const std = @import("std");
const c = @cImport({
    @cInclude("poll.h");
});

const MAX_FDS = 1024;

const Self = @This();

fileChanged: *const fn (usize) void,
inotify_fd: ?std.os.fd_t = null,

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

/// starts the file watch. This function will not return, so it is best
/// to put this function in its own thread:
///
///   const watcher_thread = try std.Thread.spawn(.{}, Watch.startWatch, .{&watcher});
///
/// Due to the nature of the poll(), behavior will almost definitely not work
/// well if files are added after the watch begins. A method for doing this
/// is intended later
pub fn startWatch(self: *Self) void {
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

            // fds[0] is inotify, so if we have data in that file descriptor,
            // we can force the data into an inotify_event structure and act on it
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

                    // Read next event from inotify
                    ptr = @alignCast(
                        @alignOf(std.os.linux.inotify_event),
                        ptr + @sizeOf(std.os.linux.inotify_event) + ev.len,
                    );
                }
            }
        }
    }
}

/// This will determine whether the inotify event indicates an actionable
/// change to the file, and if so, will call self.fileChanged
fn processInotifyEvent(self: *Self, ev: *const std.os.linux.inotify_event) void {
    // If the file was modified, it is good to know, but not
    // actionable at this time. We can set a modification flag
    // for later use. This flag and process may be unnecessary...
    // how can we have a modify followed by CLOSE_NOWRITE?
    //
    // TODO: Delete the following
    if (ev.mask & std.os.linux.IN.MODIFY == std.os.linux.IN.MODIFY) {
        for (self.wds, 0..) |wd, inx| {
            if (ev.wd == wd)
                self.modified[inx] = true;
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
    // There's a couple ways a file can be modified. The simplest
    // way is to write(), then close(). For a variety of reasons
    // due to safety, a lot of programs will write some temporary
    // file, then copy or move it in place. This will fail to
    // trigger IN_CLOSE_WRITE, so we need to detect it another
    // way. The best is to watch for events on the parent directory
    // to find move events. Note that using copy will trigger
    // a IN_CLOSE_WRITE. Without building directory watching in,
    // we can use IN_ATTRIB to satisfy the `zig build` use case,
    // which modifies attributes after moving the file.
    //
    // THIS WILL NOT WORK in the generic sense, and ultimately
    // we're going to have to watch the directory as well
    // attrib added as build process moves in place and modifies attributes
    //
    // TODO: Also watch MOVED_TO, which is on the directory...
    if (ev.mask & std.os.linux.IN.CLOSE_WRITE == std.os.linux.IN.CLOSE_WRITE or
        ev.mask & std.os.linux.IN.ATTRIB == std.os.linux.IN.ATTRIB)
    {
        for (self.wds, 0..) |wd, inx| {
            if (ev.wd == wd)
                self.fileChanged(inx);
        }
    }
}

/// adds a file to watch. The return will be a handle that will be returned
/// in the fileChanged event triffered from startWatch
pub fn addFileWatch(self: *Self, path: [:0]const u8) !usize {
    self.inotify_fd = self.inotify_fd orelse try std.os.inotify_init1(std.os.linux.IN.NONBLOCK);
    errdefer {
        std.os.close(self.inotify_fd.?);
        self.inotify_fd = null;
    }
    // zig build modification pattern: open 20, close_nowrite 10, MOVED_TO (on the directory), attrib 4
    // unix cp: OPEN, MODIFY, CLOSE_WRITE, ATTRIB
    // unix mv: MOVED_TO (on the directory)
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
