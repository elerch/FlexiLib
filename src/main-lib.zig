const std = @import("std");
const interface = @import("interface.zig");
const testing = std.testing;

const log = std.log.scoped(.@"main-lib");

// request_deinit is an optional export and will be called a the end of the
// request. Useful for deallocating memory
// export fn request_deinit() void {
// }
export fn handle_request(request: *interface.Request) callconv(.C) ?*interface.Response {
    return interface.handleRequest(request, handleRequest);
}

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
fn handleRequest(allocator: std.mem.Allocator, request: interface.Request, response: interface.ZigResponse) !void {
    _ = allocator;
    // setup
    var response_writer = response.body.writer();
    // real work
    response_writer.print(" {d}", .{request.headers_len}) catch unreachable;
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
