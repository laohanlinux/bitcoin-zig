const std = @import("std");
const hashes = @import("hashes/hash_engine.zig");
const hex = @import("hashes/hash_engine.zig").hex;

pub const BlockHeader = struct {
    /// The protocol version. Should always be 1.
    version: i32,
};

pub const Hash256 = struct {
    buf: [32]u8 = [1]u8{0} ** 32,
    h: hashes.HashEngine(hashes.HashType.sha256d),

    pub fn init() @This() {
        return .{ .h = hashes.HashEngine(hashes.HashType.sha256d).init(buf) };
    }

    pub fn to_string(self: *@This(), allocator: std.mem.Allocator) ![]const u8 {
        return hex(allocator, self.buf);
    }

    pub fn engine() hashes.HashEngine(hashes.HashType.sha256d) {
        return hashes.HashEngine(hashes.HashType.sha256d).init();
    }
};

pub const Hash160 = struct {
    buf: [16]u8 = [1]u8{0} ** 16,
    h: hashes.HashEngine(hashes.HashType.sha256),
};

/// A bitcoin transaction hash/transaction ID.
pub const Txid = Hash256;
/// A bitcoin witness transaction ID.
pub const Wtxid = Hash256;
/// A bitcoin block hash.
pub const BlockHash = Hash256;
/// SigHash
pub const SigHash = Hash256;

/// A hash of a public key.
pub const PubkeyHash = Hash160;
/// A hash of Bitcoin Script bytecode.
pub const ScriptHash = Hash256;
/// SegWit version of a public key hash.
pub const WPubkeyHash = Hash160;
/// SegWit version of a Bitcoin Script bytecode hash.
pub const WScriptHash = Hash256;

/// A hash of the Merkle tree branch or root for transactions
pub const TxMerkleNode = Hash256;
/// A hash corresponding to the Merkle tree root for witness data
pub const WitnessMerkleNode = Hash256;
/// A hash corresponding to the witness structure commitment in the coinbase transaction
pub const WitnessCommitment = Hash256;
/// XpubIdentifier as defined in BIP-32.
pub const XpubIdentifier = Hash160;

/// Bloom filter souble-SHA256 locator hash, as defined in BIP-168
pub const FilterHash = Hash256;
