const builtin = @import("builtin");
const std = @import("std");

const MAX_FDS = 1024;

const Self = @This();
const log = std.log.scoped(.watch);

const Wd = struct {
    wd: i32 = 0,
    path: ?*const []const u8 = null,
};

fileChanged: *const fn (usize) void,
inotify_fd: ?std.os.fd_t = null,

nfds_t: usize = 0,
wds: [MAX_FDS]Wd = [_]Wd{.{}} ** MAX_FDS,
dir_nfds_t: usize = 0,
dir_wds: [MAX_FDS]Wd = [_]Wd{.{}} ** MAX_FDS,
control_socket: ?std.os.socket_t = null,
watch_started: bool = false,

pub fn init(file_changed: *const fn (usize) void) Self {
    if (builtin.os.tag != .linux)
        @compileError("Unsupported OS");
    return .{
        .fileChanged = file_changed,
    };
}

pub fn deinit(self: *Self) void {
    if (self.control_socket) |s| {
        // Sockets...where Unix still pretends everything is a file, but it's not...
        log.debug("closing control socket", .{});
        std.os.closeSocket(s);
    }
    if (self.inotify_fd) |fd| {
        for (0..self.nfds_t + self.dir_nfds_t) |inx| {
            const wd = if (inx < self.nfds_t) self.wds[inx].wd else self.dir_wds[inx - self.nfds_t].wd;
            switch (std.os.errno(std.os.linux.inotify_rm_watch(fd, wd))) {
                .SUCCESS => {},
                .BADF => unreachable,
                // NOTE: Getting EINVAL, but the call looks valid to me?
                // ...and wait...not all the time?
                .INVAL => log.err("error removing watch (EINVAL). OS claims fd ({d}) or wd ({d}) is invalid", .{ self.inotify_fd.?, wd }),
                else => unreachable,
            }
        }
        std.os.close(fd);
    }
    const cwd = std.fs.cwd();
    cwd.deleteFileZ(SOCK_NAME) catch |e|
        log.err("error removing socket file " ++ SOCK_NAME ++ ": {any}", .{e});
}

const SOCK_NAME = "S.watch-control";

/// starts the file watch. This function will not return, so it is best
/// to put this function in its own thread:
///
///   const watcher_thread = try std.Thread.spawn(.{}, Watch.startWatch, .{&watcher});
///
/// Due to the nature of the poll(), behavior will almost definitely not work
/// well if files are added after the watch begins. A method for doing this
/// is intended later
pub fn startWatch(self: *Self) void {
    if (self.control_socket == null)
        self.addControlSocket(SOCK_NAME) catch @panic("could not add control socket");
    std.debug.assert(self.control_socket != null);

    while (true) {
        if (self.nfds_t == 0) {
            std.time.sleep(250);
            continue;
        }
        self.watch_started = true;

        var fds = if (self.inotify_fd == null)
            &[_]std.os.pollfd{.{ .fd = self.control_socket.?, .events = std.os.POLL.IN, .revents = undefined }}
        else
            &[_]std.os.pollfd{
                .{ .fd = self.control_socket.?, .events = std.os.POLL.IN, .revents = undefined },
                .{ .fd = self.inotify_fd.?, .events = std.os.POLL.IN, .revents = undefined },
            };

        const control_fd_inx = 0;
        const inotify_fd_inx = 1;

        //
        // NOTE: There is a std.io.poll that provides a higher level abstraction.
        // However, this API is strictly related to the use case of an open stream
        // for which we are awaiting data. In this case, we are polling for
        // an inotify event, for which no abstraction currently exists
        //
        // std.fs.watch looks really good...but it requires event based I/O,
        // which is not yet ready to be (re)added.
        log.debug("tid={d} start poll with {d} fds", .{ std.Thread.getCurrentId(), fds.len });
        if ((std.os.poll(
            fds,
            -1, // Infinite timeout
        ) catch @panic("poll error")) > 0) {
            if (fds[control_fd_inx].revents & std.os.POLL.IN == std.os.POLL.IN) { // POLLIN means "there is data to read"
                log.debug("tid={d} control event", .{std.Thread.getCurrentId()});
                // we only need one byte for what we're doing
                var control_buf: [1]u8 = undefined;

                // self.control_socket_accepted_fd = self.control_socket_accepted_fd orelse acceptSocket(self.control_socket.?);
                // const fd = self.control_socket_accepted_fd.?; // let's save some typing
                const fd = acceptSocket(self.control_socket.?);
                defer std.os.close(fd);

                var readcount = std.os.recv(fd, &control_buf, 0) catch unreachable;
                // var other_buf: [1]u8 = undefined;
                // if (std.os.recv(fd, &other_buf, 0) catch unreachable != 0)
                //     @panic("socket contains more data than expected");
                log.debug("read {d} bytes from socket: {s}", .{ readcount, std.fmt.fmtSliceHexLower(control_buf[0..readcount]) });
                if (readcount == 0) {
                    // then what?
                    log.err("tid={d} control socket with POLL.IN but no data?", .{std.Thread.getCurrentId()});
                    @panic("control event received but no data available");
                }

                switch (control_buf[0]) {
                    'c' => {
                        log.info("tid={d} continue command (reload) received on control socket", .{std.Thread.getCurrentId()});
                        continue;
                    },
                    'q' => {
                        log.info("tid={d} quit command received on control socket", .{std.Thread.getCurrentId()});
                        self.watch_started = false;
                        return;
                    },
                    else => {
                        log.err("tid={d} Unexpected command on control socket 0x{x}", .{ std.Thread.getCurrentId(), control_buf[0] });
                        if (control_buf[0] == 0xaa) // we are in a world of hurt - panic
                            @panic("seems like a buffer overrun!");
                    },
                }
            }

            // fds[1] is inotify, so if we have data in that file descriptor,
            // we can force the data into an inotify_event structure and act on it
            if (self.inotify_fd != null and fds[inotify_fd_inx].revents & std.os.POLL.IN == std.os.POLL.IN) {
                log.debug("tid={d} inotify event", .{std.Thread.getCurrentId()});
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
                    self.processInotifyEvent(ev, ptr - ev.len);
                }
            }
        }
    }
}

fn acceptSocket(socket: std.os.socket_t) std.os.socket_t {
    var sockaddr = std.net.Address.initUnix(SOCK_NAME) catch @panic("could not get sockaddr");
    var sockaddr_len: std.os.socklen_t = sockaddr.getOsSockLen();
    log.debug("tid={d} accepting on socket fd {d}", .{ std.Thread.getCurrentId(), socket });
    return std.os.accept(
        socket,
        &sockaddr.any,
        &sockaddr_len,
        0,
    ) catch @panic("could not accept connection");
}

/// This will determine whether the inotify event indicates an actionable
/// change to the file, and if so, will call self.fileChanged
fn processInotifyEvent(self: Self, ev: *const std.os.linux.inotify_event, name_ptr: [*]u8) void {
    // If the file was modified, it is good to know, but not
    // actionable at this time. We can set a modification flag
    // for later use. This flag and process may be unnecessary...
    // how can we have a modify followed by CLOSE_NOWRITE?

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
    if (ev.mask & std.os.linux.IN.CLOSE_WRITE == std.os.linux.IN.CLOSE_WRITE)
    // ev.mask & std.os.linux.IN.ATTRIB == std.os.linux.IN.ATTRIB)
    {
        for (self.wds, 0..) |wd, inx| {
            if (ev.wd == wd.wd) {
                log.debug("CLOSE_WRITE: {d}", .{wd.wd});
                self.fileChanged(inx);
                break; // stop looking when we found the file
            }
        }
    }
    if (ev.mask & std.os.linux.IN.MOVED_TO == std.os.linux.IN.MOVED_TO) {
        // This mem.span makes me deeply uncomfortable, but is how fs.watch does it
        const name = std.mem.span(@ptrCast([*:0]u8, name_ptr));
        log.debug("MOVED_TO({d}/{d}): {s}", .{ name.len, ev.len, name });
        for (self.dir_wds) |dir| {
            if (ev.wd == dir.wd) {
                for (self.wds, 0..) |wd, inx| {
                    if (inx >= self.nfds_t) {
                        log.info(
                            "file moved into watch directory but is not registered watch: {s}",
                            .{name},
                        );
                        break;
                    }

                    log.debug(
                        "name '{s}', dir '{s}', basename '{s}'",
                        .{ name, std.fs.path.dirname(dir.path.?.*).?, wd.path.?.* },
                    );
                    if (nameMatch(
                        wd.path.?.*,
                        std.fs.path.dirname(dir.path.?.*).?,
                        name,
                    )) {
                        self.fileChanged(inx);
                        break; // stop looking when we found the file
                    }
                }
                break; // once we found the directory we need to stop looking
            }
        }
    }
}

fn nameMatch(name: []const u8, dirname: []const u8, basename: []const u8) bool {
    // check total length - should be fastest fail
    if (dirname.len + basename.len + 1 != name.len) return false;
    // check beginning
    if (!std.mem.eql(u8, dirname, name[0..dirname.len])) return false;
    // check end
    if (!std.mem.eql(u8, basename, name[dirname.len + 1 ..])) return false;
    // check path seperator (assuming unix)
    return name[dirname.len] == '/';
}

test "nameMatch" {
    try std.testing.expect(nameMatch(
        "zig-out/lib/libfaas-proxy-sample-lib.so",
        "zig-out/lib",
        "libfaas-proxy-sample-lib.so",
    ));
}

/// adds a file to watch. The return will be a handle that will be returned
/// in the fileChanged event triffered from startWatch
pub fn addFileWatch(self: *Self, path: *[:0]const u8) !usize {
    self.inotify_fd = self.inotify_fd orelse try std.os.inotify_init1(std.os.linux.IN.NONBLOCK);
    errdefer {
        std.os.close(self.inotify_fd.?);
        self.inotify_fd = null;
    }
    // zig build modification pattern: open 20, close_nowrite 10, MOVED_TO (on the directory), attrib 4
    // unix cp: OPEN, MODIFY, CLOSE_WRITE, ATTRIB
    // unix mv: MOVED_TO (on the directory)
    self.wds[self.nfds_t] = .{
        .wd = try std.os.inotify_add_watchZ(
            self.inotify_fd.?,
            path.*,
            std.os.linux.IN.CLOSE_WRITE,
        ),
        .path = path,
    };
    if (self.wds[self.nfds_t].wd == -1)
        @panic("could not set watch");
    log.debug("watch added. fd {d}, wd {d}. Path {s}", .{ self.inotify_fd.?, self.wds[self.nfds_t].wd, path });
    self.nfds_t += 1;
    try self.addDirWatch(path);
    if (self.watch_started) self.reloadWatch() catch @panic("could not reload watch");
    return self.nfds_t - 1;
}

// This will add a hidden directory watch to catch OS moves into place
fn addDirWatch(self: *Self, path: *[]const u8) !void {
    const dirname = std.fs.path.dirname(path.*).?; // TODO: reimplement std.fs.path.dirname as we're getting a local in here
    log.debug("addDirWatch: dir_nfds_t: {d}, dir: {s}", .{ self.dir_nfds_t, dirname });
    if (self.dir_nfds_t > 1)
        for (0..self.dir_nfds_t) |inx|
            if (self.dir_wds[inx].path) |p|
                if (std.mem.eql(u8, std.fs.path.dirname(p.*).?, dirname))
                    return; // We are already watching this directory
    // We do not have a directory watch
    self.dir_wds[self.dir_nfds_t] = .{
        .wd = try std.os.inotify_add_watch(self.inotify_fd.?, dirname, std.os.linux.IN.MOVED_TO),
        .path = path, // we store path rather than directory because doing this without an allocator is...tough
    };
    self.dir_nfds_t += 1;
    log.debug("directory watch added. fd {d}, wd {d}, dir {s}", .{ self.inotify_fd.?, self.wds[self.nfds_t].wd, dirname });
}

fn reloadWatch(self: Self) !void {
    try self.sendControl('c');
}

pub fn stopWatch(self: Self) !void {
    try self.sendControl('q');
}

fn sendControl(self: Self, control: u8) !void {
    // Sockets...where Unix still pretends everything is a file, but it's not...
    //
    // For client processing, there are a bunch of steps, but the zig stdlib
    // saves us a bunch of work. Once we do std.net.connectUnixSocket(), we
    // get a stream back that has reader() and writer() calls
    //
    // log.debug("request to send control 0x{x}", .{control});
    if (self.control_socket == null) return; // nothing to do
    // log.debug("tid={d} opening stream", .{std.Thread.getCurrentId()});
    var stream = try std.net.connectUnixSocket(SOCK_NAME);
    defer stream.close();
    log.debug("tid={d} sending control 0x{x} on socket fd={d}", .{ std.Thread.getCurrentId(), control, stream.handle });
    try stream.writer().writeByte(control);
}

/// creates a control socket. This allows for managing the watcher. With it,
/// you can gracefully terminate the process and you can add files after the fact
fn addControlSocket(self: *Self, path: [:0]const u8) !void {
    // This function theoretically should work without requiring linux...except this inotify call,
    // which is completely linux specific
    self.inotify_fd = self.inotify_fd orelse try std.os.inotify_init1(std.os.linux.IN.NONBLOCK);
    log.debug("Established inotify file descriptor {d}", .{self.inotify_fd.?});
    errdefer {
        std.os.close(self.inotify_fd.?);
        self.inotify_fd = null;
    }
    // this should work on all systems theoretically, but I believe would work only
    // on *nix systems
    //
    // Sockets...where Unix still pretends everything is a file, but it's not...
    // We'll create a unix socket, which looks like a file on the file system
    //
    // For client processing, see comments in the sendControl function
    //
    // From the "server" perspective, we need to to this initially:
    // 1. std.os.socket: create the socket. This file descriptor should be used in poll(2) calls
    // 2. std.os.bind: tell the system where the socket is (here, it's the filesystem path)
    // 3. std.os.listen: tell the system how many simultaneous connections we can have
    //
    // At this point, clients can write to the socket (but that's not typical fs ops either)
    // To read from the socket, we need to:
    //
    // 4. std.os.accept: create a file descriptor from the socket descriptor
    // 5. std.os.recv: works just like read(2). Call lots
    // 6. std.os.close: close the fd
    //
    // On end of use, we need to std.os.closeSocket()
    const sock = try std.os.socket(
        std.os.linux.AF.LOCAL,
        std.os.linux.SOCK.STREAM | std.os.SOCK.CLOEXEC,
        0,
    );
    errdefer std.os.closeSocket(sock);

    const sockaddr = try std.net.Address.initUnix(path);

    // TODO: If this bind fails with EADDRINUSE we can probably delete the existing file
    try std.os.bind(sock, &sockaddr.any, sockaddr.getOsSockLen());
    try std.os.listen(sock, 10);
    self.control_socket = sock;
    log.debug("added control socket with fd={d}", .{sock});
}
