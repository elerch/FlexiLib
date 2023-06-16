const std = @import("std");

// C interfaces between main and libraries
pub const Header = extern struct {
    name_ptr: [*]u8,
    name_len: usize,

    value_ptr: [*]u8,
    value_len: usize,
};
pub const Response = extern struct {
    ptr: [*]u8,
    len: usize,

    headers: [*]Header,
    headers_len: usize,
};

pub const Request = extern struct {
    method: [*:0]u8,
    method_len: usize,

    content: [*]u8,
    content_len: usize,

    headers: [*]Header,
    headers_len: usize,
};

// If the library is Zig, we can use these helpers
threadlocal var allocator: ?*std.mem.Allocator = null;

const log = std.log.scoped(.interface);

pub const ZigRequest = struct {
    method: [:0]u8,
    content: []u8,
    headers: []Header,
};

pub const ZigHeader = struct {
    name: []u8,
    value: []u8,
};

pub const ZigResponse = struct {
    body: *std.ArrayList(u8),
    headers: *std.StringHashMap([]const u8),
};

pub const ZigRequestHandler = *const fn (std.mem.Allocator, ZigRequest, ZigResponse) anyerror!void;

/// This function is optional and can be exported by zig libraries for
/// initialization. If exported, it will be called once in the beginning of
/// a request and will be provided a pointer to std.mem.Allocator, which is
/// useful for reusing the parent allocator. If you're planning on using
/// the handleRequest helper below, you must use zigInit or otherwise
/// set the interface allocator in your own version of zigInit
pub fn zigInit(parent_allocator: *anyopaque) callconv(.C) void {
    allocator = @ptrCast(*std.mem.Allocator, @alignCast(@alignOf(*std.mem.Allocator), parent_allocator));
}

pub fn toZigHeader(header: Header) ZigHeader {
    return .{
        .name = header.name_ptr[0..header.name_len],
        .value = header.value_ptr[0..header.value_len],
    };
}

/// Converts a StringHashMap to the structure necessary for passing through the
/// C boundary. This will be called automatically for you via the handleRequest function
/// and is also used by the main processing loop to coerce request headers
fn toHeaders(alloc: std.mem.Allocator, headers: std.StringHashMap([]const u8)) ![*]Header {
    var header_array = try std.ArrayList(Header).initCapacity(alloc, headers.count());
    var iterator = headers.iterator();
    while (iterator.next()) |kv| {
        header_array.appendAssumeCapacity(.{
            .name_ptr = @constCast(kv.key_ptr.*).ptr,
            .name_len = kv.key_ptr.*.len,

            .value_ptr = @constCast(kv.value_ptr.*).ptr,
            .value_len = kv.value_ptr.*.len,
        });
    }
    return header_array.items.ptr;
}

/// handles a request, implementing the C interface to communicate between the
/// main program and a zig library. Most importantly, it will catch/report
/// errors appropriately and allow zig code to use standard Zig error semantics
pub fn handleRequest(request: *Request, zigRequestHandler: ZigRequestHandler) ?*Response {
    // TODO: implement another library in C or Rust or something to show
    // that anything using a C ABI can be successful
    var alloc = if (allocator) |a| a.* else {
        log.err("zigInit not called prior to handle_request. This is a coding error", .{});
        return null;
    };

    // setup response body
    var response = std.ArrayList(u8).init(alloc);

    // setup headers
    var headers = std.StringHashMap([]const u8).init(alloc);
    zigRequestHandler(
        alloc,
        .{
            .method = request.method[0..request.method_len :0],
            .content = request.content[0..request.content_len],
            .headers = request.headers[0..request.headers_len],
        },
        .{
            .body = &response,
            .headers = &headers,
        },
    ) catch |e| {
        log.err("Unexpected error processing request: {any}", .{e});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
        return null;
    };

    log.debug("response ptr: {*}", .{response.items.ptr});
    // Marshall data back for handling by server

    var rc = alloc.create(Response) catch {
        log.err("Could not allocate memory for response object. This may be fatal", .{});
        return null;
    };
    rc.ptr = response.items.ptr;
    rc.len = response.items.len;
    rc.headers = toHeaders(alloc, headers) catch |e| {
        log.err("Unexpected error processing request: {any}", .{e});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
        return null;
    };
    rc.headers_len = headers.count();
    return rc;
}
