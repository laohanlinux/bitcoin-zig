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
/// For comptime-known length data (arrays or pointers to arrays).
pub fn hex(data: anytype) [data.len * 2]u8 {
    return std.fmt.bytesToHex(data, .lower);
}

/// Convert a runtime-length slice of bytes to a hex string.
/// Caller owns the returned memory.
pub fn hexAlloc(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, data.len * 2);
    for (data, 0..) |byte, i| {
        result[i * 2] = std.fmt.digitToChar(byte >> 4, .lower);
        result[i * 2 + 1] = std.fmt.digitToChar(byte & 0x0f, .lower);
    }
    return result;
}

/// Parse a hex string into a slice of bytes.
pub inline fn parseHexBytes(allocator: std.mem.Allocator, hexStr: []const u8) ![]u8 {
    const bytes = allocator.alloc(u8, hexStr.len / 2) catch unreachable;
    _ = std.fmt.hexToBytes(bytes, hexStr) catch unreachable;
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
    const digest_size = switch (h) {
        .sha256 => 32,
        .sha256d => 32,
        .ripemd160 => 20,
        .sha512 => 64,
        .hash160 => 20,
    };

    return struct {
        buf: [digest_size]u8 = [1]u8{0} ** digest_size,
        hasher: HashEngine(h),

        const Self = @This();

        /// The size of the hash output in bytes
        pub const DIGEST_SIZE: usize = digest_size;

        /// Create a new hash with zero buffer
        pub fn init() Self {
            return Self{ .hasher = HashEngine(h).init(.{}) };
        }

        /// Create a hash engine for incremental hashing
        pub fn engine() HashEngine(h) {
            return HashEngine(h).init(.{});
        }

        /// Create a hash from a byte slice
        /// Returns null if the slice length doesn't match the expected hash size
        pub fn fromSlice(slice: []const u8) ?Self {
            if (slice.len != digest_size) {
                return null;
            }
            var result = Self{ .hasher = HashEngine(h).init(.{}) };
            @memcpy(&result.buf, slice);
            return result;
        }

        /// Create a hash from a byte array
        pub fn fromBytes(bytes: [digest_size]u8) Self {
            var result = Self{ .hasher = HashEngine(h).init(.{}) };
            result.buf = bytes;
            return result;
        }

        /// Compute the hash of the given data
        pub fn hash(data: []const u8) Self {
            var result = Self{ .hasher = HashEngine(h).init(.{}) };
            HashEngine(h).hash(data, &result.buf);
            return result;
        }

        /// Convert to hex string
        pub fn toHex(self: *const Self) [digest_size * 2]u8 {
            return hex(&self.buf);
        }

        /// Convert to hex string (reversed byte order, like Bitcoin txid display)
        pub fn toHexReversed(self: *const Self) [digest_size * 2]u8 {
            var reversed: [digest_size]u8 = undefined;
            for (0..digest_size) |i| {
                reversed[i] = self.buf[digest_size - 1 - i];
            }
            return hex(&reversed);
        }

        /// Get the underlying bytes
        pub fn asBytes(self: *const Self) *const [digest_size]u8 {
            return &self.buf;
        }

        /// Check if two hashes are equal
        pub fn eql(self: *const Self, other: *const Self) bool {
            return std.mem.eql(u8, &self.buf, &other.buf);
        }

        /// Check if the hash is all zeros
        pub fn isZero(self: *const Self) bool {
            for (self.buf) |byte| {
                if (byte != 0) return false;
            }
            return true;
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
    const hexHash = hex(&hash);
    try std.testing.expectEqualSlices(u8, "a51a910ecba8a599555b32133bf1829455d55fe576677b49cb561d874077385c", &hexHash);
}

test "ripemd160" {
    const message = "message digest";
    var hash: [20]u8 = undefined;
    HashEngine(HashType.ripemd160).hash(message, &hash);
    const hexHash = hex(&hash);
    try std.testing.expectEqualSlices(u8, "5d0689ef49d2fae572b881b123a85ffa21595f36", &hexHash);
}
