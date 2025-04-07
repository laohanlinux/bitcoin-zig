const std = @import("std");
const big = @import("std").math.big;
const script = @import("./script/script.zig");
const hash = @import("../hashes/hash_engine.zig");
const Script = script.Script;
const Hash256 = hash.HashEngine(.sha256);
const Hash256d = hash.HashEngine(.sha256d);
const hash_type = @import("../hash_types.zig");
const Txid = hash_type.Txid;
const encode = @import("../consensus/encode.zig");
const VarInt = encode.VarInt;
const DecoderOption = encode.DecoderOption;
const EncoderOption = encode.EncoderOption;
const Reader = encode.Reader;

/// A Bitcoin transaction, which describes an authenticated movement of coins.
///
/// If any inputs have nonempty witnesses, the entire transaction is serialized
/// in the post-BIP141 Segwit format which includes a list of witnesses. If all
/// inputs have empty witnesses, the transaction is serialized in the pre-BIP141
/// format.
///
/// There is one major exception to this: to avoid deserialization ambiguity,
/// if the transaction has no inputs, it is serialized in the BIP141 style. Be
/// aware that this differs from the transaction format in PSBT, which _never_
/// uses BIP141. (Ordinarily there is no conflict, since in PSBT transactions
/// are always unsigned and therefore their inputs have empty witnesses.)
///
/// The specific ambiguity is that Segwit uses the flag bytes `0001` where an old
/// serializer would read the number of transaction inputs. The old serializer
/// would interpret this as "no inputs, one output", which means the transaction
/// is invalid, and simply reject it. Segwit further specifies that this encoding
/// should *only* be used when some input has a nonempty witness; that is,
/// witness-less transactions should be encoded in the traditional format.
///
/// However, in protocols where transactions may legitimately have 0 inputs, e.g.
/// when parties are cooperatively funding a transaction, the "00 means Segwit"
/// heuristic does not work. Since Segwit requires such a transaction be encoded
/// in the original transaction format (since it has no inputs and therefore
/// no input witnesses), a traditionally encoded transaction may have the `0001`
/// Segwit flag in it, which confuses most Segwit parsers including the one in
/// Bitcoin Core.
///
/// We therefore deviate from the spec by always using the Segwit witness encoding
/// for 0-input transactions, which results in unambiguously parseable transactions.
/// https://developer.bitcoin.org/devguide/transactions.html
///           Each input spends a previous output
//    +---------+--------+--------+---------+
//    | Version | Inputs | Outputs | Locktime |
//    +---------+--------+--------+---------+
//       The Main Parts Of Transaction 0
//                  |
//                  v
//    +---------+--------+--------+---------+
//    | Version | Inputs | Outputs | Locktime |
//    +---------+--------+--------+---------+
//       The Main Parts Of Transaction 1
// Each output waits as an Unspent TX Output (UTXO) until a later input spends it
pub const Transaction = struct {
    /// The protocol version, is currently expected to be 1 or 2 (BIP 68).
    version: i32,
    /// Block number before which this transaction is valid, or 0 for
    /// valid immediately.
    lock_time: u32,
    /// List of inputs
    input: std.ArrayList(TxIn),
    /// List of outputs
    output: std.ArrayList(TxOut),
    allocator: std.mem.Allocator,
    /// Computes a "normalized TXID" which does not include any signatures.
    /// This gives a way to identify a transaction that is ``the same'' as
    /// another in the sense of having same inputs and outputs.
    // pub fn ntxid(self: *const @This(), allocator: std.mem.Allocator) Hash256 {
    //     var tx = Transaction{ .version = self.version, .lock_time = self.lock_time, .input = undefined, .output = undefined, .allocator = allocator };
    //     var input = std.ArrayList(TxIn).init(allocator);
    //     var output = std.ArrayList(TxOut).init(allocator);
    //     tx.input = input.toOwnedSlice() catch unreachable;
    //     tx.output = output.toOwnedSlice() catch unreachable;
    //     // return tx;

    //     const h = Hash256.init();
    //     return h;
    // }

    /// Computes the txid. For non-segwit transactions this will be identical
    /// to the output of `wtxid()`, but for segwit transactions,
    /// this will give the correct txid (not including witnesses) while `wtxid`
    /// will also hash witnesses.
    pub fn txid(_: *const @This(), _: std.mem.Allocator) Txid {
        const h = Hash256.init();
        return h;
    }

    pub fn is_coin_base(self: *const @This()) bool {
        return self.input.items.len == 1 and self.input.items[0].prev_out.n == 0;
    }

    /// consensusEncode
    pub fn consensusEncode(_: *const @This(), _: anytype) ![]u8 {
        // var len: usize = 0;
        // // version
        // len += try encode.Encodable(i32).init(self.version).consensusEncode(writer);
        // // witness
        // var hasWitness: bool = false;
        // for (self.input.items) |input| {
        //     hasWitness = input.witness != null and input.witness.?.len > 0;
        //     if (hasWitness) {
        //         break;
        //     }
        // }
        // // input
        // len += try encode.Encodable(VarInt).init(self.input.items.len).consensusEncode(writer);
        // // output
        // len += try encode.Encodable(VarInt).init(self.output.items.len).consensusEncode(writer);
        // // lock_time
        // len += try encode.Encodable(u32).init(self.lock_time).consensusEncode(writer);
    }
};

//
// An input of a transaction. It contains the location of the previous
// transaction's input that it claims and a signature that matches the
// output's public key.
//
pub const TxIn = struct {
    /// The reference to the previous output that is being used an an input
    previousOutput: OutPoint,
    /// The script which pushes values on the stack which will cause
    /// the referenced output's script to accept
    scriptSig: Script,
    /// The sequence number, which suggests to miners which of two
    /// conflicting transactions should be preferred, or 0xFFFFFFFF
    /// to ignore this feature. This is generally never used since
    /// the miner behaviour cannot be enforced.
    sequence: isize,
    /// Witness data: an array of byte-arrays.
    /// Note that this field is *not* (de)serialized with the rest of the TxIn in
    /// Encodable/Decodable, as it is (de)serialized at the end of the full
    /// Transaction. It *is* (de)serialized with the rest of the TxIn in other
    /// (de)serialization routines.
    witness: ?[][]u8 = null,
    const Self = @This();

    pub fn init(prev_out: OutPoint, script_sig: Script, sequence: isize) Self {
        return .{ .previousOutput = prev_out, .scriptSig = script_sig, .sequence = sequence };
    }

    pub fn consensusEncode(_: *const @This(), _: anytype) ![]u8 {
        @panic("not implemented");
    }
};

// An output of a transaction. It contains the public key that the next input
// must be signed with to claim it.
pub const TxOut = struct {
    /// The value of the output, in satoshis
    value: u64,
    /// The script which must satisfy for the output to be spent
    script_pubkey: Script,

    const Self = @This();

    pub fn default(allocator: std.mem.Allocator) Self {
        return .{ .value = 0xffffffffffffffff, .script_pubkey = Script.default(allocator) };
    }

    pub fn init(value: i64, script_pubkey: Script) Self {
        return .{ .value = value, .script_pubkey = script_pubkey };
    }

    pub fn deinit(self: Self) void {
        self.script_pubkey.deinit();
    }
};

pub const InPoint = struct {
    ptx: ?Transaction,
    n: isize,
    const Self = @This();
    pub fn init(tx: *Transaction, n: isize) !Self {
        return Self{ .ptx = tx, .n = n };
    }

    pub fn set_null(self: *Self) void {
        self.ptx = null;
        self.n = -1;
    }

    pub fn is_null(self: *Self) bool {
        return (self.ptx == null and self.n == -1);
    }

    // pub fn to_string(self: *Self) ![]u8 {
    //     if (self.is_null()) {
    //         return "InPoint(null, -1)";
    //     }
    //     const str = try std.fmt.allocPrint(self.allocator, "InPoint({any}, {any})", .{self.ptx, self.n});
    //     return str;
    // }
};

/// A reference to a transaction output
pub const OutPoint = struct {
    /// The referenced transaction's txid
    txid: Txid,
    /// The index of the referenced output in its transaction's vout
    vout: u32,

    const Self = @This();
    /// Creates a "null" `OutPoint`.
    ///
    /// This value is used for coinbase transactions because they don't have
    /// any previous outputs.
    pub const Null = Self.init(Txid.init(), std.math.maxInt(u32));

    /// create a new [OutPoint]
    pub fn init(txid: Txid, vout: u32) Self {
        return .{ .txid = txid, .vout = vout };
    }

    /// Creates a "null" `OutPoint`
    ///
    /// This value is used for coinbase transactions because they don't have
    /// any previous outputs.
    pub fn nullOutPint() Self {
        return Self.init(Txid.init(), std.math.maxInt(u32));
    }

    pub inline fn is_null(self: *Self) bool {
        return self.vout == Self.Null.vout and std.mem.eql(u8, self.txid.buf, Self.Null.txid.buf);
    }

    pub fn to_string(self: *Self, allocator: std.mem.Allocator) ![]u8 {
        const str_hash = try self.txid.to_string(allocator);
        defer allocator.free(str_hash);
        const str = try std.fmt.allocPrint(allocator, "OutPoint({s}, {d})", .{ str_hash, self.vout });
        return str;
    }

    pub fn fromString(str: []const u8) ParseOutPointError!Self {
        if (str.len > 75) { // 64 + 1 + 10
            return .TooLong;
        }
        @panic("unambiguously");
    }

    pub fn consensusEncode(self: *const Self, writer: anytype) encode.Error!usize {
        const txLen = try encode.Encodable(Txid).init(self.txid).consensusEncode(writer);
        const voutLen = try encode.Encodable(u32).init(self.vout).consensusEncode(writer);
        return txLen + voutLen;
    }
};

/// An error in parsing an OutPoint
pub const ParseOutPointError = error{
    /// Error in TXID part.
    Txid,
    /// Error in vout part.
    Vout,
    /// Error in general format.
    Format,
    /// Size exceeds max.
    TooLong,
    /// Vout part is not strictly numeric without leading zeroes.
    VoutNotCanonical,
};

pub fn parseOutPointErrorString(allocator: std.mem.Allocator, parseOutPointError: ParseOutPointError) []const u8 {
    switch (parseOutPointError) {
        .Txid => return std.fmt.allocPrint(allocator, "error parsing TXID", .{}) catch unreachable,
        .Vout => return std.fmt.allocPrint(allocator, "error parsing vout", .{}) catch unreachable,
        .Format => return std.fmt.allocPrint(allocator, "OutPoint not in <txid>:<vout> format", .{}) catch unreachable,
        .TooLong => return std.fmt.allocPrint(allocator, "vout should be at most 10 digits", .{}) catch unreachable,
        .VoutNotCanonical => return std.fmt.allocPrint(allocator, "no leading zeroes or + allowed in vout part", .{}) catch unreachable,
    }
}

test "bigint" {
    const Managed = std.math.big.int.Managed;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var a = try Managed.init(allocator);
    var b = try Managed.init(allocator);

    try a.set(1990273423429836742364234234234);
    try b.set(1990273423429836742364234234234);

    try a.add(&a, &b);
    std.debug.print("{any}\n", .{a});

    try a.mul(&a, &b);
    std.debug.print("{any}\n", .{a});
    var out = try OutPoint.init(0, std.testing.allocator);
    defer out.deinit();
    std.debug.print("{any}\n", .{out.is_null()});
    out.set_null();
    std.debug.print("{any}\n", .{out.is_null()});

    const out_str = try out.to_string(std.testing.allocator);
    defer std.testing.allocator.free(out_str);
    std.debug.print("{s}\n", .{out_str});
}

test "self allocator" {
    const Person = struct {
        name: [10]u8,
        address: std.ArrayList(u8),
        const Self = @This();

        fn init() !*Self {
            const p = try std.testing.allocator.create(Self);
            p.* = .{
                .name = [10]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 },
                .address = std.ArrayList(u8).init(std.testing.allocator),
            };
            //p.address.appendSlice("hello word") catch unreachable;
            return p;
        }

        fn deinit(self: *Self) void {
            self.address.deinit();
            std.testing.allocator.destroy(self);
        }
    };
    const e = Person.init() catch unreachable;
    e.address.appendSlice("hello word") catch unreachable;

    e.deinit();

    //std.debug.print("{s}\n", .{p.address.items});
}
