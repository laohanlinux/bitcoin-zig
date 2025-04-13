const std = @import("std");
const hash = @import("../hashtypes/lib.zig");
const transaction = @import("transaction.zig");
const BlockHash = hash.BlockHash;
const TxMerkleNode = hash.TxMerkleNode;
const Transaction = transaction.Transaction;

pub const BlockHeader = struct {
    /// The protocol version. Should always be 1.
    version: i32,
    /// Reference to the previous block in the chain
    prev_blockhash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block
    merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner
    time: u32,
    /// The target value below which the blockhash must lie, encoded as a
    /// a float (with well-defined rounding, of course)
    bits: u32,
    /// The nonce, selected to obtain a low enough blockhash
    nonce: u32,
};

/// A Bitcoin block, which is a collection of transactions with an attached
/// proof of work.
pub const Block = struct {
    /// The block header
    header: BlockHeader,
    // List of transactions contained in the block
    // txdata: Vec<Transaction>
};
