const std = @import("std");
const crypto = @import("std").crypto;
// const h160 = @import("hash160.zig");
const Ripemd160 = @import("ripemd160.zig").Ripemd160;
pub const HashType = enum {
    sha256,
    sha256d,
    sha512,
    hash160,
    ripemd160,
};

fn sha256d() type {
    return struct {
        hasher: crypto.hash.sha2.Sha256,
        const Self = @This();

        pub fn init() Self {
            return .{ .hasher = crypto.hash.sha2.Sha256.init(.{}) };
        }

        pub fn update(self: *Self, data: []const u8) void {
            self.hasher.update(data);
        }

        pub fn final(self: *Self, out: *[32]u8) void {
            var hash: [32]u8 = undefined;
            self.hasher.final(&hash);
            var sha256d_hasher = crypto.hash.sha2.Sha256.init(.{});
            sha256d_hasher.update(&hash);
            sha256d_hasher.final(out);
        }
    };
}

/// Convert a slice of bytes to a hex string.
pub inline fn hex(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    const hex_str = try std.fmt.allocPrint(allocator, "{x}", .{std.fmt.fmtSliceHexLower(data[0..])});
    return hex_str;
}

/// Hash engine for a given hash type.
pub fn HashEngine(h: HashType) type {
    return struct {
        hasher: switch (h) {
            .sha256 => crypto.hash.sha2.Sha256,
            .sha256d => sha256d(),
            .hash160 => @compileError("not implemented"),
            .ripemd160 => Ripemd160,
            .sha512 => crypto.hash.sha2.Sha512,
        },
        pub const Options = struct {};
        const Self = @This();

        pub fn init(_: Options) Self {
            return .{
                .hasher = switch (h) {
                    .sha256 => crypto.hash.sha2.Sha256.init(.{}),
                    .sha256d => sha256d().init(),
                    .hash160 => @compileError("not implemented"),
                    .ripemd160 => Ripemd160{ .bytes = undefined },
                    .sha512 => crypto.hash.sha2.Sha512.init(.{}),
                },
            };
        }

        // TODO: Implement hash160
        pub fn hash(input: []const u8, out: *[
            switch (h) {
                .sha256 => 32,
                .sha256d => 32,
                .hash160 => 20,
                .ripemd160 => 20,
                .sha512 => 64,
            }
        ]u8) void {
            switch (h) {
                .hash160 => {
                    // const _hash = h160.hash160(b) catch unreachable;
                    // std.mem.copyForwards(u8, out, _hash);
                    @panic("not implemented");
                },
                .ripemd160 => {
                    const _hash = Ripemd160.hash(input).bytes;
                    std.mem.copyForwards(u8, out, _hash[0..20]);
                },
                else => @compileError("not implemented"),
            }
        }

        pub fn update(self: *Self, data: []const u8) void {
            if (h == .hash160 or h == .ripemd160) {
                @compileError("not implemented, only hash() is supported");
            } else {
                self.hasher.update(data);
            }
        }

        pub fn finish(
            self: *Self,
            out: *[
                switch (h) {
                    .sha256 => 32,
                    .sha256d => 32,
                    .hash160 => @compileError("not implemented, only hash() is supported"),
                    .ripemd160 => 20, // 160 / 8
                    .sha512 => 64,
                }
            ]u8,
        ) void {
            self.hasher.final(out);
        }
    };
}

test "hash engine" {
    const message = "The quick brown fox jumps over the lazy dog.";
    var engine = HashEngine(HashType.sha256).init(.{});

    // Update the hash with our message
    engine.update(message);

    // Create buffer for the hash output
    var hash: [32]u8 = undefined;
    engine.finish(&hash); // Pass the address of the hash array

    // Print the hash in hexadecimal format
    const hex_hash = try hex(std.testing.allocator, &hash);
    defer std.testing.allocator.free(hex_hash);
    std.debug.print("hash: {s}\n", .{hex_hash});

    // Create expected hash for comparison
    var expected: [32]u8 = undefined;
    var direct_hasher = std.crypto.hash.sha2.Sha256.init(.{});
    direct_hasher.update(message);
    direct_hasher.final(&expected);

    // Compare results
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "sha256d" {
    const message = "The quick brown fox jumps over the lazy dog.";
    var engine = HashEngine(HashType.sha256d).init();
    engine.update(message);
    var hash: [32]u8 = undefined;
    engine.finish(&hash);
    const hex_hash = try hex(std.testing.allocator, &hash);
    defer std.testing.allocator.free(hex_hash);
    std.debug.print("hash: {s}\n", .{hex_hash});

    const hash256 = HashType.sha256;
    std.debug.print("{}\n", .{hash256});
}

test "ripemd160" {
    const message = "message digest";
    var hash: [20]u8 = undefined;
    HashEngine(HashType.ripemd160).hash(message, &hash);
    const hex_hash = try hex(std.testing.allocator, &hash);
    defer std.testing.allocator.free(hex_hash);
    try std.testing.expectEqualSlices(u8, "5d0689ef49d2fae572b881b123a85ffa21595f36", hex_hash);
}
