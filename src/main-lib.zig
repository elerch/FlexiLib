const std = @import("std");
const testing = std.testing;

const Response = extern struct {
    ptr: [*]u8,
    len: usize,
};

var child_allocator = std.heap.raw_c_allocator; // raw allocator recommended for use in arenas
var arena: std.heap.ArenaAllocator = undefined;

export fn handle_request() *Response {
    arena = std.heap.ArenaAllocator.init(child_allocator);
    var allocator = arena.allocator();
    var al = std.ArrayList(u8).init(allocator);
    var writer = al.writer();

    writer.print(" 2.", .{}) catch unreachable;

    // Cannot simply return &Blah. Need to assign to var first
    var rc = &Response{
        .ptr = al.items.ptr,
        .len = al.items.len,
    };
    return rc;
}

/// having request_deinit allows for a general deinit as well
export fn request_deinit() void {
    std.log.debug("deinit", .{});
    arena.deinit();
}

export fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "basic add functionality" {
    try testing.expect(add(3, 7) == 10);
}
