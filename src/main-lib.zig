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
    @export(interface.zigInit, .{ .name = "zigInit", .linkage = .strong });
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
fn handleRequest(allocator: std.mem.Allocator, response: *interface.ZigResponse) !void {
    // setup
    var response_writer = response.body.writer();
    // real work
    for (response.request.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "host")) {
            if (std.mem.startsWith(u8, h.value, "iam")) {
                try response_writer.print("iam response", .{});
                return;
            }
            break;
        }
    }
    for (response.request.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "x-slow")) {
            std.time.sleep(std.time.ns_per_ms * (std.fmt.parseInt(usize, h.value, 10) catch 1000));
            try response_writer.print("i am slow\n\n", .{});
            return;
        }
    }
    for (response.request.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "x-log-this")) {
            try response.writeAll(h.value);
            break;
        }
    }
    for (response.request.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "x-status")) {
            response.status = @enumFromInt(std.fmt.parseInt(u10, h.value, 10) catch 500);
            break;
        }
    }
    for (response.request.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "x-throw"))
            return error.Thrown;
    }
    try response_writer.print(" {d}", .{response.request.headers.len});
    var headers = std.ArrayList(std.http.Header).init(allocator);
    try headers.appendSlice(response.headers);
    try headers.append(.{ .name = "X-custom-foo", .value = "bar" });
    response.headers = try headers.toOwnedSlice();
}

test "handle_request" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var aa = arena.allocator();
    interface.zigInit(&aa);
    const headers: []interface.Header = @constCast(&[_]interface.Header{.{
        .name_ptr = @ptrCast(@constCast("GET".ptr)),
        .name_len = 3,
        .value_ptr = @ptrCast(@constCast("GET".ptr)),
        .value_len = 3,
    }});
    var req = interface.Request{
        .target = @ptrCast(@constCast("/".ptr)),
        .target_len = 1,
        .method = @ptrCast(@constCast("GET".ptr)),
        .method_len = 3,
        .content = @ptrCast(@constCast("GET".ptr)),
        .content_len = 3,
        .headers = headers.ptr,
        .headers_len = headers.len,
    };
    const response = handle_request(&req).?;
    try testing.expectEqualStrings(" 1", response.ptr[0..response.len]);
    try testing.expectEqual(@as(usize, 1), response.headers_len);
    try testing.expectEqualStrings("X-custom-foo", response.headers[0].name_ptr[0..response.headers[0].name_len]);
    try testing.expectEqualStrings("bar", response.headers[0].value_ptr[0..response.headers[0].value_len]);
}

test "lib can write data directly" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var aa = arena.allocator();
    interface.zigInit(&aa);
    const headers: []interface.Header = @constCast(&[_]interface.Header{.{
        .name_ptr = @ptrCast(@constCast("x-log-this".ptr)),
        .name_len = "x-log-this".len,
        .value_ptr = @ptrCast(@constCast("I am a teapot".ptr)),
        .value_len = "I am a teapot".len,
    }});
    var req = interface.Request{
        .target = @ptrCast(@constCast("/".ptr)),
        .target_len = 1,
        .method = @ptrCast(@constCast("GET".ptr)),
        .method_len = 3,
        .content = @ptrCast(@constCast("GET".ptr)),
        .content_len = 3,
        .headers = headers.ptr,
        .headers_len = headers.len,
    };
    const response = handle_request(&req).?;
    try testing.expectEqual(@as(usize, 1), response.headers_len);
    try testing.expectEqualStrings("X-custom-foo", response.headers[0].name_ptr[0..response.headers[0].name_len]);
    try testing.expectEqualStrings("bar", response.headers[0].value_ptr[0..response.headers[0].value_len]);
    try testing.expectEqualStrings("I am a teapot 1", response.ptr[0..response.len]);
}
test "lib can write data directly and still throw" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var aa = arena.allocator();
    interface.zigInit(&aa);
    const headers: []interface.Header = @constCast(&[_]interface.Header{ .{
        .name_ptr = @ptrCast(@constCast("x-log-this".ptr)),
        .name_len = "x-log-this".len,
        .value_ptr = @ptrCast(@constCast("I am a teapot".ptr)),
        .value_len = "I am a teapot".len,
    }, .{
        .name_ptr = @ptrCast(@constCast("x-throw".ptr)),
        .name_len = "x-throw".len,
        .value_ptr = @ptrCast(@constCast("I am a teapot".ptr)),
        .value_len = "I am a teapot".len,
    } });
    var req = interface.Request{
        .target = @ptrCast(@constCast("/".ptr)),
        .target_len = 1,
        .method = @ptrCast(@constCast("GET".ptr)),
        .method_len = 3,
        .content = @ptrCast(@constCast("GET".ptr)),
        .content_len = 3,
        .headers = headers.ptr,
        .headers_len = headers.len,
    };
    const response = handle_request(&req).?;
    try testing.expectEqual(@as(usize, 500), response.status);
    try testing.expectEqualStrings("I am a teapot", response.ptr[0..response.len]);
}
test "lib can set status, update data directly and still throw" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var aa = arena.allocator();
    interface.zigInit(&aa);
    const headers: []interface.Header = @constCast(&[_]interface.Header{ .{
        .name_ptr = @ptrCast(@constCast("x-log-this".ptr)),
        .name_len = "x-log-this".len,
        .value_ptr = @ptrCast(@constCast("I am a teapot".ptr)),
        .value_len = "I am a teapot".len,
    }, .{
        .name_ptr = @ptrCast(@constCast("x-throw".ptr)),
        .name_len = "x-throw".len,
        .value_ptr = @ptrCast(@constCast("I am a teapot".ptr)),
        .value_len = "I am a teapot".len,
    }, .{
        .name_ptr = @ptrCast(@constCast("x-status".ptr)),
        .name_len = "x-status".len,
        .value_ptr = @ptrCast(@constCast("418".ptr)),
        .value_len = "418".len,
    } });
    var req = interface.Request{
        .target = @ptrCast(@constCast("/".ptr)),
        .target_len = 1,
        .method = @ptrCast(@constCast("GET".ptr)),
        .method_len = 3,
        .content = @ptrCast(@constCast("GET".ptr)),
        .content_len = 3,
        .headers = headers.ptr,
        .headers_len = headers.len,
    };
    const response = handle_request(&req).?;
    try testing.expectEqual(@as(usize, 418), response.status);
    try testing.expectEqualStrings("I am a teapot", response.ptr[0..response.len]);
}
