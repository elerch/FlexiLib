const std = @import("std");

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

pub fn toHeaders(alloc: std.mem.Allocator, headers: std.StringHashMap([]const u8)) ![*]Header {
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

var allocator: ?*std.mem.Allocator = null;

pub const ZigResponse = struct {
    body: *std.ArrayList(u8),
    headers: *std.StringHashMap([]const u8),
};

/// This function is optional and can be exported by zig libraries for
/// initialization. If exported, it will be called once in the beginning of
/// a request and will be provided a pointer to std.mem.Allocator, which is
/// useful for reusing the parent allocator
pub fn zigInit(parent_allocator: *anyopaque) callconv(.C) void {
    allocator = @ptrCast(*std.mem.Allocator, @alignCast(@alignOf(*std.mem.Allocator), parent_allocator));
}

pub const ZigRequestHandler = *const fn (std.mem.Allocator, Request, ZigResponse) anyerror!void;

const log = std.log.scoped(.interface);
pub fn handleRequest(request: *Request, zigRequestHandler: ZigRequestHandler) ?*Response {
    // TODO: implement another library in C or Rust or something to show
    // that anything using a C ABI can be successful
    var alloc = if (allocator) |a| a.* else @panic("zigInit not called prior to handle_request. This is a coding error");

    // setup response body
    var response = std.ArrayList(u8).init(alloc);

    // setup headers
    var headers = std.StringHashMap([]const u8).init(alloc);
    zigRequestHandler(alloc, request.*, .{
        .body = &response,
        .headers = &headers,
    }) catch |e| {
        log.err("Unexpected error processing request: {any}", .{e});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
        return null;
    };

    log.debug("response ptr: {*}", .{response.items.ptr});
    // Marshall data back for handling by server

    var rc = alloc.create(Response) catch @panic("OOM");
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
