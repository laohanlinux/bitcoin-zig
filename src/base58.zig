const b58 = @import("./base58/lib.zig");
const std = @import("std");

pub const Encoder58 = struct {
    enc: b58.Encoder,
    dest: ?[]u8,
    allocator: std.mem.Allocator = std.heap.page_allocator,
    const Self = @This();
    /// Initialize Encoder with options
    pub fn init() Self {
        const encoder = b58.Encoder.init(.{});
        return .{ .enc = encoder, .dest = null };
    }

    /// Pass an `allocator` & `source` bytes buffer. `encodeAlloc` will allocate a buffer
    /// to write into. It may also realloc as needed. Returned value is base58 encoded string.
    pub fn encode(self: *Self, source: []const u8) anyerror![]u8 {
        self.dest = try self.enc.encodeAlloc(self.allocator, source);
        return self.dest.?;
    }

    /// Pass a `source` and a `dest` to write encoded value into. `encode` returns a
    /// `usize` indicating how many bytes were written. Sizing/resizing, `dest` buffer is up to the caller.
    pub fn define(self: *Self) void {
        if (self.dest) |dest| {
            self.allocator.free(dest);
        }
    }
};

pub const Decoder58 = struct {
    dec: b58.Decoder,
    buf: ?[]const u8,
    const Self = @This();

    /// Initialize Decoder
    pub fn init(buf: []const u8) Self {
        const decoder = b58.Decoder.init(.{});
        return .{ .dec = decoder, .buf = buf };
    }

    /// Pass a `encoded` and a `dest` to write decoded value into. `decode` returns a
    /// `usize` indicating how many bytes were written. Sizing/resizing, `dest` buffer is up to the caller.
    pub fn decode(self: *Self, dest: []u8) !usize {
        return self.dec.decode(self.buf, dest);
    }

    pub fn decodeAlloc(self: *Self, allocator: std.mem.Allocator) ![]u8 {
        return self.dec.decodeAlloc(allocator, self.buf.?);
    }
};

pub fn hash160() ![]const u8 {
    return null;
}

test "should decodeAlloc value correctly" {}
