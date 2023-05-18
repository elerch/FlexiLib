const std = @import("std");
const interface = @import("interface.zig");
const testing = std.testing;

const log = std.log.scoped(.@"main-lib");

var allocator: ?*std.mem.Allocator = null;
const Response = struct {
    body: *std.ArrayList(u8),
    headers: *std.StringHashMap([]const u8),
};

/// This function is optional and can be exported by zig libraries for
/// initialization. If exported, it will be called once in the beginning of
/// a request and will be provided a pointer to std.mem.Allocator, which is
/// useful for reusing the parent allocator
export fn zigInit(parent_allocator: *anyopaque) void {
    allocator = @ptrCast(*std.mem.Allocator, @alignCast(@alignOf(*std.mem.Allocator), parent_allocator));
}
export fn handle_request() ?*interface.Response {
    // TODO: implement another library in C or Rust or something to show
    // that anything using a C ABI can be successful
    var alloc = if (allocator) |a| a.* else @panic("zigInit not called prior to handle_request. This is a coding error");

    // setup response body
    var response = std.ArrayList(u8).init(alloc);

    // setup headers
    var headers = std.StringHashMap([]const u8).init(alloc);
    handleRequest(.{
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

    var rc = alloc.create(interface.Response) catch @panic("OOM");
    rc.ptr = response.items.ptr;
    rc.len = response.items.len;
    rc.headers = interface.toHeaders(alloc, headers) catch |e| {
        log.err("Unexpected error processing request: {any}", .{e});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
        return null;
    };
    rc.headers_len = headers.count();
    return rc;
}

/// request_deinit is an optional export and will be called a the end of the
/// request. Useful for deallocating memory
// export fn request_deinit() void {
// }

// ************************************************************************
// Boilerplate ^^, Custom code vv
// ************************************************************************
//
// handleRequest function here is the last line of boilerplate and the
// entry to a request
fn handleRequest(response: Response) !void {
    // setup
    var response_writer = response.body.writer();
    // real work
    response_writer.print(" 2.", .{}) catch unreachable;
    try response.headers.put("X-custom-foo", "bar");
    log.info("handlerequest header count {d}", .{response.headers.count()});
}

test "handle_request" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var aa = arena.allocator();
    allocator = &aa;
    const response = handle_request().?;
    try testing.expectEqualStrings(" 2.", response.ptr[0..response.len]);
    try testing.expectEqualStrings("X-custom-foo", response.headers[0].name_ptr[0..response.headers[0].name_len]);
    try testing.expectEqualStrings("bar", response.headers[0].value_ptr[0..response.headers[0].value_len]);
}
