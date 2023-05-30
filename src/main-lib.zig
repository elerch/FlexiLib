const std = @import("std");
const interface = @import("interface.zig");
const testing = std.testing;

const log = std.log.scoped(.@"main-lib");

// request_deinit is an optional export and will be called a the end of the
// request. Useful for deallocating memory
// export fn request_deinit() void {
// }

/// handle_request will be called on a single request, but due to the preservation
/// of restrictions imposed by the calling interface, it should generally be more
/// useful to call into the interface library to let it do the conversion work
/// on your behalf
export fn handle_request(request: *interface.Request) callconv(.C) ?*interface.Response {
    return interface.handleRequest(request, handleRequest);
}

// zigInit is an optional export called at the beginning of a request. It will
// be passed an allocator (which...shh...is an arena allocator). Since the
// interface library provides a request handler that requires a built-in allocator,
// if you are using the interface library, you will need to also include this
// export
comptime {
    @export(
        interface.zigInit,
        .{ .name = "zigInit", .linkage = .Strong },
    );
}

// ************************************************************************
// Boilerplate ^^, Custom code vv
// ************************************************************************
//
// handleRequest function here is the last line of boilerplate and the
// entry to a request
fn handleRequest(allocator: std.mem.Allocator, request: interface.ZigRequest, response: interface.ZigResponse) !void {
    _ = allocator;
    // setup
    var response_writer = response.body.writer();
    // real work
    response_writer.print(" {d}", .{request.headers.len}) catch unreachable;
    try response.headers.put("X-custom-foo", "bar");
    log.info("handlerequest header count {d}", .{response.headers.count()});
}

test "handle_request" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var aa = arena.allocator();
    interface.zigInit(&aa);
    var headers: []interface.Header = @constCast(&[_]interface.Header{.{
        .name_ptr = @ptrCast([*:0]u8, @constCast("GET".ptr)),
        .name_len = 3,
        .value_ptr = @ptrCast([*:0]u8, @constCast("GET".ptr)),
        .value_len = 3,
    }});
    var req = interface.Request{
        .method = @ptrCast([*:0]u8, @constCast("GET".ptr)),
        .method_len = 3,
        .content = @ptrCast([*:0]u8, @constCast("GET".ptr)),
        .content_len = 3,
        .headers = headers.ptr,
        .headers_len = 1,
    };
    const response = handle_request(&req).?;
    try testing.expectEqualStrings(" 1", response.ptr[0..response.len]);
    try testing.expectEqualStrings("X-custom-foo", response.headers[0].name_ptr[0..response.headers[0].name_len]);
    try testing.expectEqualStrings("bar", response.headers[0].value_ptr[0..response.headers[0].value_len]);
}
