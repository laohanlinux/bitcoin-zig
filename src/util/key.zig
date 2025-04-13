const std = @import("std");
const Network = @import("../network/lib.zig").constants.Network;

const Allocator = std.mem.Allocator;
const Secp256k1 = std.crypto.ecc.Secp256k1;
const b58 = @import("b58.zig");

pub const Error = error{
    Base58Error,
    Secp256k1Error,
} || b58.Error;

/// A Bitcoin ECDSA public key
pub const PublicKey = struct {
    /// Whether this public key should be serialized as compressed
    compressed: bool,
    /// The actual ECDSA key
    key: Secp256k1,

    const Self = @This();
    /// Write the public key into a writer
    pub fn writeInto(self: *const Self, writer: anytype) void {
        if (self.compressed) {
            writer.writeAll(self.key.toCompressedSec1()[0..]) catch unreachable;
        } else {
            writer.writeAll(self.key.toUncompressedSec1()[0..]) catch unreachable;
        }
    }

    /// Serialize the public key to bytes
    pub fn toBytes(self: *const Self, allocator: Allocator) ![]u8 {
        var buf = std.ArrayList(u8).init(allocator);
        self.writeInto(buf.writer());
        return buf.toOwnedSlice();
    }

    pub fn asBytes(self: *const Self) ![]u8 {
        if (self.compressed) {
            return self.key.toCompressedSec1()[0..1];
        } else {
            return self.key.toUncompressedSec1()[0..];
        }
    }

    /// Deserialize a public key from a slice
    pub fn fromSlice(bytes: []const u8) Error!PublicKey {
        const compressed = switch (bytes.len) {
            33 => true,
            65 => false,
            else => {
                return Error.Base58Error;
            },
        };
        const key = try Secp256k1.fromSec1(bytes);
        return PublicKey{ .key = key, .compressed = compressed };
    }
};

/// A Bitcoin ECDSA private key
pub const PrivateKey = struct {
    /// Whether this private key should be serialized as compressed
    compressed: bool,
    /// The network on which this key should be used
    network: Network,
    /// The actual ECDSA key
    key: [32]u8 = undefined,

    const Self = @This();
    /// Creates a public key from this private key
    pub fn publicKey(self: *const Self) PublicKey {
        const public_point = Secp256k1.basePoint.mul(self.key, .little) catch unreachable;
        return PublicKey{ .key = public_point, .compressed = self.compressed };
    }

    /// Serialize the private key to bytes
    pub fn tobytes(self: *const Self, allocator: Allocator) Error![]u8 {
        var buf = std.ArrayList(u8).initCapacity(allocator, self.key.len) catch |err| {
            std.log.err("failed to allocator memory: {any}", .{err});
            return Error.Base58Error;
        };
        buf.appendSlice(self.key) catch unreachable;
        return buf.toOwnedSlice();
    }

    /// Format the private key to WIF format.
    pub fn formatWif(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        var ret = [_]u8{0} ** 34;
        // 0
        switch (self.network) {
            .bitcoin => {
                ret[0] = 128;
            },
            .testnet, .regtest => {
                ret[0] = 239;
            },
        }
        // 1..32
        std.mem.copyForwards(u8, ret[1..33], self.key[0..]);
        // 33
        if (self.compressed) {
            ret[33] = 1;
            return b58.checkEncodeSliceToFmt(allocator, ret[0..]);
        } else {
            return b58.checkEncodeSliceToFmt(allocator, ret[0..33]);
        }
    }

    /// Get WIF encoding of this private key.
    pub fn toWif(self: *const Self, allocator: Allocator) ![]u8 {
        return self.formatWif(allocator);
    }

    /// Parse a WIF encoded private key.
    pub fn fromWif(allocator: std.mem.Allocator, bytes: []const u8) Error!PrivateKey {
        var data = try b58.fromCheck(allocator, bytes);
        errdefer allocator.free(data);
        const compressed = switch (data.len) {
            34 => true,
            33 => false,
            else => return Error.Base58Error,
        };
        const network = switch (data[0]) {
            128 => Network.bitcoin,
            239 => Network.testnet,
            else => return Error.Base58Error,
        };
        var private_key = PrivateKey{ .compressed = compressed, .network = network };
        @memcpy(private_key.key[0..], data[1..33]);
        return private_key;
    }
};

test "private key" {
    var area = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer area.deinit();
    const privateKey = try PrivateKey.fromWif(area.allocator(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");
    try std.testing.expectEqual(privateKey.network, .testnet);
    try std.testing.expect(privateKey.compressed);
    const toWif = try privateKey.toWif(area.allocator());
    try std.testing.expectEqualSlices(u8, toWif, "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");
    // const publicKeyBytes = try publicKey.toBytes(area.allocator());
    // try std.testing.expectEqualSlices(u8, publicKeyBytes, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    std.debug.print("private key: {any}\n", .{Network.bitcoin});
}
