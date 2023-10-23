const std = @import("std");

// C interfaces between main and libraries
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

    status: usize,

    reason_ptr: [*]u8,
    reason_len: usize,
};

pub const Request = extern struct {
    target: [*]const u8,
    target_len: usize,

    method: [*:0]u8,
    method_len: usize,

    content: [*]u8,
    content_len: usize,

    headers: [*]Header,
    headers_len: usize,
};

// If the library is Zig, we can use these helpers
threadlocal var allocator: ?*std.mem.Allocator = null;

const log = std.log.scoped(.interface);

pub const ZigRequest = struct {
    target: []const u8,
    method: [:0]u8,
    content: []u8,
    headers: std.http.Headers,
};

pub const ZigHeader = struct {
    name: []u8,
    value: []u8,
};

pub const ZigResponse = struct {
    status: std.http.Status = .ok,
    reason: ?[]const u8 = null,
    body: *std.ArrayList(u8),
    headers: std.http.Headers,
    request: ZigRequest,
    prepend: std.ArrayList(u8),

    pub fn write(res: *ZigResponse, bytes: []const u8) !usize {
        return res.prepend.writer().write(bytes);
    }

    pub fn writeAll(res: *ZigResponse, bytes: []const u8) !void {
        return res.prepend.writer().writeAll(bytes);
    }

    pub fn writer(res: *ZigResponse) std.io.Writer {
        return res.prepend.writer().writer();
    }

    pub fn finish(res: *ZigResponse) !void {
        if (res.prepend.items.len > 0)
            try res.body.insertSlice(0, res.prepend.items);
        res.prepend.deinit();
    }
};

pub const ZigRequestHandler = *const fn (std.mem.Allocator, *ZigResponse) anyerror!void;

/// This function is optional and can be exported by zig libraries for
/// initialization. If exported, it will be called once in the beginning of
/// a request and will be provided a pointer to std.mem.Allocator, which is
/// useful for reusing the parent allocator. If you're planning on using
/// the handleRequest helper below, you must use zigInit or otherwise
/// set the interface allocator in your own version of zigInit
pub fn zigInit(parent_allocator: *anyopaque) callconv(.C) void {
    allocator = @ptrCast(@alignCast(parent_allocator));
}

/// Converts a StringHashMap to the structure necessary for passing through the
/// C boundary. This will be called automatically for you via the handleRequest function
/// and is also used by the main processing loop to coerce request headers
fn toHeaders(alloc: std.mem.Allocator, headers: std.http.Headers) ![*]Header {
    var header_array = try std.ArrayList(Header).initCapacity(alloc, headers.list.items.len);
    log.err("enter ({d})", .{headers.list.items.len});
    for (headers.list.items) |*field| {
        // var name = try alloc.dupe(u8, field.name);
        // var val = try alloc.dupe(u8, field.value);
        // log.err(" response header name {s}, val {s}", .{ name, val });
        header_array.appendAssumeCapacity(.{
            .name_ptr = @constCast(field.name.ptr),
            .name_len = field.name.len,

            .value_ptr = @constCast(field.value.ptr),
            .value_len = field.value.len,
        });
    }
    log.err("exit", .{});
    return header_array.items.ptr;
}

/// handles a request, implementing the C interface to communicate between the
/// main program and a zig library. Most importantly, it will catch/report
/// errors appropriately and allow zig code to use standard Zig error semantics
pub fn handleRequest(request: *Request, zigRequestHandler: ZigRequestHandler) ?*Response {
    // TODO: implement another library in C or Rust or something to show
    // that anything using a C ABI can be successful
    var alloc = if (allocator) |a| a.* else {
        log.err("zigInit not called prior to handle_request. This is a coding error", .{});
        return null;
    };

    // setup response body
    var response = std.ArrayList(u8).init(alloc);

    // setup headers
    var response_headers = std.http.Headers.init(alloc);
    var request_headers = std.http.Headers.init(alloc);
    for (0..request.headers_len) |i|
        request_headers.append(
            request.headers[i].name_ptr[0..request.headers[i].name_len],
            request.headers[i].value_ptr[0..request.headers[i].value_len],
        ) catch |e| {
            log.err("Unexpected error processing request: {any}", .{e});
            if (@errorReturnTrace()) |trace| {
                std.debug.dumpStackTrace(trace.*);
            }
            return null;
        };

    //     if (serve_result.prepended_request_data_len > 0) {
    //     var al = std.ArrayList(u8).initCapacity(allocator, slice.len + serve_result.prepended_request_data_len);
    //     defer al.deinit();
    //     al.appendSliceAssumeCapacity(serve_result.prepended_request_data[0..serve_result.prepended_request_data_len]);
    //     al.appendSliceAssumeCapacity(slice);
    //     slice = al.toOwnedSlice();
    // }

    var prepend = std.ArrayList(u8).init(alloc);
    var zig_response = ZigResponse{
        .headers = response_headers,
        .body = &response,
        .prepend = prepend,
        .request = .{
            .content = request.content[0..request.content_len],
            .target = request.target[0..request.target_len],
            .method = request.method[0..request.method_len :0],
            .headers = request_headers,
        },
    };
    zigRequestHandler(
        alloc,
        &zig_response,
    ) catch |e| {
        log.err("Unexpected error processing request: {any}", .{e});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
        return null;
    };

    // Marshall data back for handling by server

    var rc = alloc.create(Response) catch {
        log.err("Could not allocate memory for response object. This may be fatal", .{});
        return null;
    };
    zig_response.finish() catch {
        log.err("Could not allocate memory for response object. This may be fatal", .{});
        return null;
    };
    rc.ptr = response.items.ptr;
    rc.len = response.items.len;
    rc.headers = toHeaders(alloc, response_headers) catch |e| {
        log.err("Unexpected error processing request: {any}", .{e});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
        return null;
    };
    //log.err("headers len: {d} header[0] name: {s}", .{ rc.headers_len, rc.headers[0].name_ptr[0..rc.headers[0].name_len] });
    rc.headers_len = response_headers.list.items.len;
    rc.status = if (zig_response.status == .ok) 0 else @intFromEnum(zig_response.status);
    rc.reason_len = 0;
    if (zig_response.reason) |*r| {
        rc.reason_ptr = @constCast(r.ptr);
        rc.reason_len = r.len;
    }

    return rc;
}
