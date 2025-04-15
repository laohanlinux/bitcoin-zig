const std = @import("std");
const crypto = @import("std").crypto;
const _Ripemd160 = @import("ripemd160.zig").Ripemd160;

/// The type of hash to use
pub const HashType = enum {
    sha256,
    sha256d,
    sha512,
    ripemd160,
    hash160,
};

fn Sha256d() type {
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

/// Hash160 is a combination of SHA-256 and RIPEMD-160 hash functions.
/// It first applies SHA-256 on the input and then applies RIPEMD-160 on the result.
/// This is commonly used in Bitcoin for address generation.
/// Hash160(x) = RIPEMD-160(SHA-256(x))
fn Hash160() type {
    return struct {
        const Self = @This();

        pub fn init() Self {
            return .{};
        }

        pub fn hash(input: []const u8, out: *[20]u8) void {
            var tmp: [32]u8 = undefined;
            {
                var hashEngine = HashEngine(.sha256).init(.{});
                hashEngine.update(input);
                hashEngine.finish(&tmp);
            }
            var hasher = _Ripemd160.hash(tmp[0..32]);
            std.mem.copyForwards(u8, out, hasher.bytes[0..20]);
        }
    };
}

fn Ripemd160() type {
    return struct {
        const Self = @This();

        pub fn init() Self {
            return .{};
        }

        pub fn hash(input: []const u8, out: *[20]u8) void {
            var hasher = _Ripemd160.hash(input);
            std.mem.copyForwards(u8, out, hasher.bytes[0..20]);
        }
    };
}

/// Convert a slice of bytes to a hex string.
pub inline fn hex(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const hex_str = try std.fmt.allocPrint(allocator, "{x}", .{std.fmt.fmtSliceHexLower(data[0..])});
    return hex_str;
}

/// Parse a hex string into a slice of bytes.
pub inline fn parseHexBytes(allocator: std.mem.Allocator, hexStr: []const u8) []u8 {
    var bytes = allocator.alloc(u8, hexStr.len / 2) catch unreachable;
    var i: usize = 0;
    while (i < hexStr.len) : (i += 2) {
        bytes[i / 2] = std.fmt.parseInt(u8, hexStr[i .. i + 2], 16) catch unreachable;
    }
    return bytes;
}

/// A hashing engine which bytes can be serialized into. It is expected
/// to implement the `io::Write` trait, but to never return errors under
/// any conditions.
pub fn HashEngine(h: HashType) type {
    return struct {
        hasher: switch (h) {
            .sha256 => crypto.hash.sha2.Sha256,
            .sha256d => Sha256d(),
            .ripemd160 => Ripemd160(),
            .sha512 => crypto.hash.sha2.Sha512,
            .hash160 => Hash160(),
        },
        pub const Options = struct {};
        const Self = @This();

        pub fn init(_: Options) Self {
            return .{
                .hasher = switch (h) {
                    .sha256 => crypto.hash.sha2.Sha256.init(.{}),
                    .sha256d => Sha256d().init(),
                    .ripemd160 => Ripemd160().init(),
                    .sha512 => crypto.hash.sha2.Sha512.init(.{}),
                    .hash160 => Hash160().init(),
                },
            };
        }

        pub fn toHasher(self: *const Self) switch (h) {
            .sha256 => crypto.hash.sha2.Sha256,
            .sha256d => Sha256d(),
            .ripemd160 => Ripemd160(),
            .sha512 => crypto.hash.sha2.Sha512,
            .hash160 => Hash160(),
        } {
            return self.hasher;
        }

        pub fn hash(input: []const u8, out: *[
            switch (h) {
                .sha256 => 32,
                .sha256d => 32,
                .ripemd160 => 20,
                .sha512 => 64,
                .hash160 => 20,
            }
        ]u8) void {
            switch (h) {
                .ripemd160 => {
                    Ripemd160().hash(input, out);
                },
                .sha256, .sha256d => {
                    var hashEngine = Self.init(.{});
                    hashEngine.update(input);
                    hashEngine.finish(out);
                },
                .hash160 => {
                    Hash160().hash(input, out);
                },
                else => @compileError("not implemented"),
            }
        }

        pub fn update(self: *Self, data: []const u8) void {
            if (h == .ripemd160 or h == .hash160) {
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
                    .ripemd160 => 20, // 160 / 8
                    .sha512 => 64,
                    .hash160 => 20,
                }
            ]u8,
        ) void {
            self.hasher.final(out);
        }
    };
}

pub fn Hash(h: HashType) type {
    return struct {
        buf: [
            switch (h) {
                .sha256 => 32,
                .sha256d => 32,
                .ripemd160 => 20,
                .sha512 => 64,
                .hash160 => 20,
            }
        ]u8 = [1]u8{0} ** switch (h) {
            .sha256 => 32,
            .sha256d => 32,
            .ripemd160 => 20,
            .sha512 => 64,
            .hash160 => 20,
        },
        h: HashEngine(h),

        pub fn init() @This() {
            return .{ .h = HashEngine(h).init(.{}) };
        }

        pub fn engine() HashEngine(h) {
            return HashEngine(h).init(.{});
        }

        pub fn fromSlice(_: []const u8) @This() {
            @panic("not implemented");
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
    // std.debug.print("hash: {s}\n", .{hex_hash});

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
    var engine = HashEngine(HashType.sha256d).init(.{});
    engine.update(message);
    var hash: [32]u8 = undefined;
    engine.finish(&hash);
    const hex_hash = try hex(std.testing.allocator, &hash);
    defer std.testing.allocator.free(hex_hash);
}

test "ripemd160" {
    const message = "message digest";
    var hash: [20]u8 = undefined;
    HashEngine(HashType.ripemd160).hash(message, &hash);
    const hex_hash = try hex(std.testing.allocator, &hash);
    defer std.testing.allocator.free(hex_hash);
    try std.testing.expectEqualSlices(u8, "5d0689ef49d2fae572b881b123a85ffa21595f36", hex_hash);
}
