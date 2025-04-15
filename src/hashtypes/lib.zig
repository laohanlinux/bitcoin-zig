const std = @import("std");
const hashes = @import("../hashes/lib.zig");
const hashEngine = hashes.engine;
const HashType = hashEngine.HashType;
const hex = hashEngine.hex;

pub const BlockHeader = struct {
    /// The protocol version. Should always be 1.
    version: i32,
};

pub fn HashTrait(comptime hash_type: HashType) type {
    // check if hash_type is valid
    _ = hashEngine.HashEngine(hash_type).init(.{});
    return struct {
        buf: [hash_type.digest_size]u8 = [1]u8{0} ** hash_type.digest_size,
        h: hashEngine.HashEngine(hash_type),

        pub fn init() @This() {
            return .{ .h = hashEngine.HashEngine(hash_type).init(.{}) };
        }

        pub fn engine() hashEngine.HashEngine(hash_type) {
            return hashEngine.HashEngine(hash_type).init(.{});
        }
    };
}

pub const Hash256 = struct {
    buf: [32]u8 = [1]u8{0} ** 32,
    h: hashEngine.HashEngine(hashEngine.HashType.sha256),

    pub fn init() @This() {
        return .{ .h = hashEngine.HashEngine(hashEngine.HashType.sha256).init(.{}) };
    }

    pub fn engine() hashEngine.HashEngine(hashEngine.HashType.sha256) {
        return hashEngine.HashEngine(hashEngine.HashType.sha256).init(.{});
    }

    pub fn hash(input: []const u8, out: *[32]u8) void {
        hashEngine.HashEngine(.sha256).hash(input, out);
    }
};

pub const Hash256D = struct {
    buf: [32]u8 = [1]u8{0} ** 32,
    h: hashes.HashEngine(hashes.HashType.sha256d),

    pub fn init() @This() {
        return .{ .h = hashes.HashEngine(.sha256d).init(.{}) };
    }

    pub fn initWithBuff(buf: [32]u8) @This() {
        var h256: @This() = .{ .h = hashes.HashEngine(hashes.HashType.sha256d).init(.{}) };
        std.mem.copyForwards(u8, h256.buf[0..], buf[0..]);
        return h256;
    }

    pub fn toString(self: *@This(), allocator: std.mem.Allocator) ![]const u8 {
        return hex(allocator, self.buf);
    }

    pub fn toOwned(self: @This()) [32]u8 {
        return self.buf;
    }

    pub fn engine() hashes.HashEngine(.sha256d) {
        return hashes.HashEngine(.sha256d).init(.{});
    }
};

/// A 160-bit hash.
pub const Hash160 = struct {
    buf: [20]u8 = [1]u8{0} ** 20,
    h: hashEngine.HashEngine(.hash160),

    pub fn init() @This() {
        return .{ .h = hashEngine.HashEngine(.hash160).init(.{}) };
    }

    pub fn fromHash(_hash: [20]u8) @This() {
        return .{ .h = hashEngine.HashEngine(.hash160).init(.{}), .buf = _hash };
    }

    pub fn hash(input: []const u8, out: *[20]u8) void {
        const engine = hashEngine.HashEngine(.hash160);
        engine.hash(input, out);
    }
};

/// A bitcoin transaction hash/transaction ID.
pub const Txid = Hash256D;
/// A bitcoin witness transaction ID.
pub const Wtxid = Hash256D;
/// A bitcoin block hash.
pub const BlockHash = Hash256D;
/// SigHash
pub const SigHash = Hash256D;

/// A hash of a public key.
pub const PubkeyHash = Hash160;
/// A hash of Bitcoin Script bytecode.
pub const ScriptHash = Hash160;
/// SegWit version of a public key hash.
pub const WPubkeyHash = Hash160;
/// SegWit version of a Bitcoin Script bytecode hash.
pub const WScriptHash = Hash256;

/// A hash of the Merkle tree branch or root for transactions
pub const TxMerkleNode = Hash256D;
/// A hash corresponding to the Merkle tree root for witness data
pub const WitnessMerkleNode = Hash256D;
/// A hash corresponding to the witness structure commitment in the coinbase transaction
pub const WitnessCommitment = Hash256D;
/// XpubIdentifier as defined in BIP-32.
pub const XpubIdentifier = Hash160;

/// Bloom filter souble-SHA256 locator hash, as defined in BIP-168
pub const FilterHash = Hash256D;
