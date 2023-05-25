const Self = @This();
const std = @import("std");

allocator: std.mem.Allocator,

pub const ParsedConfig = struct {
    key_value_map: *std.StringArrayHashMap([]u8),
    value_key_map: *std.StringArrayHashMap(*std.ArrayList([]u8)),

    config_allocator: std.mem.Allocator,
    const SelfConfig = @This();

    var by_keys: std.StringArrayHashMap([]u8) = undefined;
    var by_values: std.StringArrayHashMap(*std.ArrayList([]u8)) = undefined;

    pub fn init(config_allocator: std.mem.Allocator) SelfConfig {
        by_keys = std.StringArrayHashMap([]u8).init(config_allocator);
        by_values = std.StringArrayHashMap(*std.ArrayList([]u8)).init(config_allocator);
        return SelfConfig{
            .config_allocator = config_allocator,
            .key_value_map = &by_keys,
            .value_key_map = &by_values,
        };
    }

    pub fn deinit(self: *SelfConfig) void {
        for (self.key_value_map.keys(), self.key_value_map.values()) |k, v| {
            self.config_allocator.free(k); // this is also the key in value_key_map
            self.config_allocator.free(v);
        }

        self.key_value_map.deinit();
        for (self.value_key_map.values()) |v| {
            // The string in the value array is the same as the one in the key
            // no need to free
            // for (v.items) |item| {
            //     self.config_allocator.free(item);
            // }
            v.deinit();
            self.config_allocator.destroy(v);
        }
        // These were already freed above
        // for (self.value_key_map.keys()) |*k| {
        //     self.config_allocator.free(k.*);
        // }
        self.value_key_map.deinit();
    }
};

pub fn init(allocator: std.mem.Allocator) Self {
    return Self{
        .allocator = allocator,
    };
}

/// Based on a reader, the return will be an ordered list of entries. The
/// key is a path prefix, while the value is the library to use
/// caller owns the allocated memory
pub fn parse(self: Self, reader: anytype) !ParsedConfig {
    const ws = " \t";
    var rc = ParsedConfig.init(self.allocator);
    errdefer rc.deinit();
    while (try reader.readUntilDelimiterOrEofAlloc(self.allocator, '\n', std.math.maxInt(usize))) |line| {
        defer self.allocator.free(line);
        const nocomments = std.mem.trim(u8, @constCast(&std.mem.split(u8, line, "#")).first(), ws);
        var data_iterator = std.mem.split(u8, nocomments, "=");
        var key = std.mem.trim(u8, data_iterator.first(), ws); // first never fails
        if (key.len == 0) continue;
        var value = std.mem.trim(u8, data_iterator.next() orelse return error.NoValueForKey, ws);
        // keys should be putNoClobber, but values can be put.
        // Because we have to dup the memory here though, we want to
        // manage duplicate values seperately
        var dup_key = try self.allocator.dupe(u8, key);
        var dup_value = try self.allocator.dupe(u8, value);
        try rc.key_value_map.putNoClobber(dup_key, dup_value);
        if (!rc.value_key_map.contains(value)) {
            var keys = try self.allocator.create(std.ArrayList([]u8));
            keys.* = std.ArrayList([]u8).init(self.allocator);
            try rc.value_key_map.put(dup_value, keys);
        }
        try rc.value_key_map.get(value).?.append(dup_key);
    }
    return rc;
}

test "gets config from a stream" {
    var allocator = std.testing.allocator;
    var stream = std.io.fixedBufferStream(
        \\# This is a simple "path prefix" = dynamic library path mapping
        \\  # no reordering will be done, so you must do things most -> least specific
        \\   
        \\
        \\foo =     bar
        \\
        \\baz= qux# what *is* this?
        \\
        \\
        \\bar =foo
        \\qaz=foo
    );

    var config = try Self.init(allocator).parse(stream.reader());
    defer config.deinit();
    try std.testing.expectEqual(@as(usize, 4), config.key_value_map.keys().len);
    try std.testing.expectEqual(@as(usize, 3), config.value_key_map.keys().len);
    try std.testing.expectEqual(@as(usize, 2), config.value_key_map.get("foo").?.items.len);
}
