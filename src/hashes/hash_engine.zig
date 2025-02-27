const std = @import("std");
const crypto = @import("std").crypto;

pub const HashType = enum {
    sha256,
    sha256d,
    sha512,
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

pub inline fn hex(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    var result = try std.ArrayList(u8).initCapacity(allocator, data.len * 2);
    var writer = result.writer();
    for (data) |byte| {
        try writer.print("{x}", .{byte});
    }
    return result.toOwnedSlice();
}

pub fn HashEngine(h: HashType) type {
    return struct {
        hasher: switch (h) {
            .sha256 => crypto.hash.sha2.Sha256,
            .sha256d => sha256d(),
            .sha512 => crypto.hash.sha2.Sha512,
        },
        const Self = @This();

        pub fn init() Self {
            return .{ .hasher = switch (h) {
                .sha256 => crypto.hash.sha2.Sha256.init(.{}),
                .sha256d => sha256d().init(),
                .sha512 => crypto.hash.sha2.Sha512.init(.{}),
            } };
        }

        pub fn update(self: *Self, data: []const u8) void {
            self.hasher.update(data);
        }

        pub fn finish(self: *Self, out: *[
            switch (h) {
                .sha256 => 32,
                .sha256d => 32,
                .sha512 => 64,
            }
        ]u8) void {
            self.hasher.final(out);
        }
    };
}

test "hash engine" {
    const message = "The quick brown fox jumps over the lazy dog.";
    var engine = HashEngine(HashType.sha256).init();

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
