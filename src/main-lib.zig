const std = @import("std");
const interface = @import("interface.zig");
const testing = std.testing;

const log = std.log.scoped(.@"main-lib");

// The main program will look for exports during the request lifecycle:
// zigInit (optional): called at the beginning of a request, includes pointer to an allocator
// handle_request: called with request data, expects response data
// request_deinit (optional): called at the end of a request to allow resource cleanup
//
// Setup for these is aided by the interface library as shown below

// zigInit is an optional export called at the beginning of a request. It will
// be passed an allocator (which...shh...is an arena allocator). Since the
// interface library provides a request handler that requires a built-in allocator,
// if you are using the interface's handleRequest function as shown above,
// you will need to also include this export. To customize, just do something
// like this:
//
// export fn zigInit(parent_allocator: *anyopaque) callconv(.C) void {
//   // your code here, just include the next line
//   interface.zigInit(parent_allocator);
// }
//
comptime {
    @export(interface.zigInit, .{ .name = "zigInit", .linkage = .Strong });
}

/// handle_request will be called on a single request, but due to the preservation
/// of restrictions imposed by the calling interface, it should generally be more
/// useful to call into the interface library to let it do the conversion work
/// on your behalf
export fn handle_request(request: *interface.Request) callconv(.C) ?*interface.Response {
    // The interface library provides a handleRequest function that will handle
    // marshalling data back and forth from the C format used for the interface
    // to a more Zig friendly format. It also allows usage of zig errors. To
    // use, pass in the request and the zig function used to handle the request
    // (here called "handleRequest"). The function signature must be:
    //
    // fn (std.mem.Allocator, interface.ZigRequest, interface.ZigResponse) !void
    //
    return interface.handleRequest(request, handleRequest);
}

// request_deinit is an optional export and will be called a the end of the
// request. Useful for deallocating memory. Since this is zig code and the
// allocator used is an arena allocator, all allocated memory will be automatically
// cleaned up by the main program at the end of a request
//
// export fn request_deinit() void {
// }

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
    for (request.headers) |h| {
        const header = interface.toZigHeader(h);
        // std.debug.print("\n{s}: {s}\n", .{ header.name, header.value });
        if (std.ascii.eqlIgnoreCase(header.name, "host") and std.mem.startsWith(u8, header.value, "iam")) {
            try response_writer.print("iam response", .{});
            return;
        }
        if (std.ascii.eqlIgnoreCase(header.name, "x-slow")) {
            std.time.sleep(std.time.ns_per_ms * (std.fmt.parseInt(usize, header.value, 10) catch 1000));
            try response_writer.print("i am slow\n\n", .{});
            return;
        }
    }
    try response_writer.print(" {d}", .{request.headers.len});
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
