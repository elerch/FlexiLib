const std = @import("std");
const interface = @import("interface.zig");
const testing = std.testing;

const log = std.log.scoped(.@"main-lib");
var child_allocator = std.heap.raw_c_allocator; // raw allocator recommended for use in arenas
var arena: std.heap.ArenaAllocator = undefined;

const Response = struct {
    body: *std.ArrayList(u8),
    headers: *std.StringHashMap([]const u8),
};

export fn handle_request() ?*interface.Response {
    arena = std.heap.ArenaAllocator.init(child_allocator);
    var allocator = arena.allocator();

    // setup response body
    var response = std.ArrayList(u8).init(allocator);

    // setup headers
    var headers = std.StringHashMap([]const u8).init(allocator);
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

    var rc = allocator.create(interface.Response) catch @panic("OOM");
    rc.ptr = response.items.ptr;
    rc.len = response.items.len;
    rc.headers = interface.toHeaders(allocator, headers) catch |e| {
        log.err("Unexpected error processing request: {any}", .{e});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
        return null;
    };
    rc.headers_len = headers.count();
    return rc;
}

/// having request_deinit allows for a general deinit as well
export fn request_deinit() void {
    arena.deinit();
}

// ************************************************************************
// Boilerplate ^^, Custom code below
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
    defer request_deinit();
    child_allocator = std.testing.allocator;
    const response = handle_request().?;
    try testing.expectEqualStrings(" 2.", response.ptr[0..response.len]);
    try testing.expectEqualStrings("X-custom-foo", response.headers[0].name_ptr[0..response.headers[0].name_len]);
    try testing.expectEqualStrings("bar", response.headers[0].value_ptr[0..response.headers[0].value_len]);
}
