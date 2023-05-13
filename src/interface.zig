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
    method: [*]u8,
    method_len: usize,

    content: [*]u8,
    content_len: usize,

    headers: [*]Header,
    headers_len: usize,
};

pub fn toHeaders(allocator: std.mem.Allocator, headers: std.StringHashMap([]const u8)) ![*]Header {
    var header_array = try std.ArrayList(Header).initCapacity(allocator, headers.count());
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
