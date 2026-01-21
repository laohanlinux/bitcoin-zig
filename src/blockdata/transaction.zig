const std = @import("std");
const big = @import("std").math.big;
const script = @import("script.zig");
const hash = @import("../hashes/lib.zig").engine;
const Script = script.Script;
const Hash256 = hash.HashEngine(.sha256);
const Hash256d = hash.HashEngine(.sha256d);
const hash_type = @import("../hashtypes/lib.zig");
const Txid = hash_type.Txid;
const Wtxid = hash_type.Wtxid;
const encode = @import("../consensus/lib.zig").encode;
const VarInt = encode.VarInt;
const Encodable = encode.Encodable;
const Decodable = encode.Decodable;
const DecoderOption = encode.DecoderOption;
const EncoderOption = encode.EncoderOption;
const Reader = encode.Reader;

/// Segwit marker byte
const SEGWIT_MARKER: u8 = 0x00;
/// Segwit flag byte
const SEGWIT_FLAG: u8 = 0x01;

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

    const Self = @This();

    /// Create a new transaction
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .version = 2,
            .lock_time = 0,
            .input = std.ArrayList(TxIn).init(allocator),
            .output = std.ArrayList(TxOut).init(allocator),
            .allocator = allocator,
        };
    }

    /// Free transaction resources
    pub fn deinit(self: *Self) void {
        for (self.input.items) |*txin| {
            txin.deinit();
        }
        self.input.deinit();
        for (self.output.items) |*txout| {
            txout.deinit();
        }
        self.output.deinit();
    }

    /// Check if any input has witness data
    fn hasWitness(self: *const Self) bool {
        for (self.input.items) |txin| {
            if (txin.witness) |w| {
                if (w.len > 0) return true;
            }
        }
        return false;
    }

    /// Computes the txid. For non-segwit transactions this will be identical
    /// to the output of `wtxid()`, but for segwit transactions,
    /// this will give the correct txid (not including witnesses) while `wtxid`
    /// will also hash witnesses.
    pub fn txid(self: *const Self, allocator: std.mem.Allocator) !Txid {
        // Serialize without witness data
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        const writer = buffer.writer();

        _ = try self.encodeWithoutWitness(writer);

        // Double SHA256 hash
        var result: Txid = Txid.init();
        Hash256d.hash(buffer.items, &result.buf);
        return result;
    }

    /// Computes the wtxid (witness txid)
    pub fn wtxid(self: *const Self, allocator: std.mem.Allocator) !Wtxid {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        const writer = buffer.writer();

        _ = try self.consensusEncode(writer);

        var result: Wtxid = Wtxid.init();
        Hash256d.hash(buffer.items, &result.buf);
        return result;
    }

    /// Check if this is a coinbase transaction
    pub fn isCoinBase(self: *const Self) bool {
        return self.input.items.len == 1 and self.input.items[0].previousOutput.is_null();
    }

    /// Encode transaction without witness data (for txid calculation)
    fn encodeWithoutWitness(self: *const Self, writer: anytype) encode.Error!usize {
        var len: usize = 0;

        // Version
        len += try Encodable(i32).init(self.version).consensusEncode(writer);

        // Input count
        len += try Encodable(VarInt).init(VarInt.init(@intCast(self.input.items.len))).consensusEncode(writer);

        // Inputs (without witness)
        for (self.input.items) |txin| {
            len += try txin.consensusEncode(writer);
        }

        // Output count
        len += try Encodable(VarInt).init(VarInt.init(@intCast(self.output.items.len))).consensusEncode(writer);

        // Outputs
        for (self.output.items) |txout| {
            len += try txout.consensusEncode(writer);
        }

        // Lock time
        len += try Encodable(u32).init(self.lock_time).consensusEncode(writer);

        return len;
    }

    /// Consensus encode the transaction
    pub fn consensusEncode(self: *const Self, writer: anytype) encode.Error!usize {
        var len: usize = 0;
        const has_witness = self.hasWitness();

        // Version
        len += try Encodable(i32).init(self.version).consensusEncode(writer);

        // If we have witness data or no inputs, use segwit format
        if (has_witness or self.input.items.len == 0) {
            // Segwit marker and flag
            writer.writeByte(SEGWIT_MARKER) catch return encode.Error.IoError;
            writer.writeByte(SEGWIT_FLAG) catch return encode.Error.IoError;
            len += 2;
        }

        // Input count
        len += try Encodable(VarInt).init(VarInt.init(@intCast(self.input.items.len))).consensusEncode(writer);

        // Inputs
        for (self.input.items) |txin| {
            len += try txin.consensusEncode(writer);
        }

        // Output count
        len += try Encodable(VarInt).init(VarInt.init(@intCast(self.output.items.len))).consensusEncode(writer);

        // Outputs
        for (self.output.items) |txout| {
            len += try txout.consensusEncode(writer);
        }

        // Witness data (if present)
        if (has_witness or self.input.items.len == 0) {
            for (self.input.items) |txin| {
                len += try txin.encodeWitness(writer);
            }
        }

        // Lock time
        len += try Encodable(u32).init(self.lock_time).consensusEncode(writer);

        return len;
    }

    /// Consensus decode a transaction
    pub fn consensusDecode(option: DecoderOption, reader: Reader) encode.Error!Self {
        const allocator = option.allocator orelse return encode.Error.ParseFailed;

        // Version
        const version = try Decodable(i32).consensusDecode(option, reader);

        // Check for segwit marker
        const marker = reader.readByte() catch return encode.Error.IoError;
        var has_witness = false;
        var input_count: u64 = 0;

        if (marker == SEGWIT_MARKER) {
            // Segwit transaction
            const flag = reader.readByte() catch return encode.Error.IoError;
            if (flag != SEGWIT_FLAG) {
                return encode.Error.UnsupportedSegwitFlag;
            }
            has_witness = true;
            const varint = try VarInt.consensusDecode(option, reader);
            input_count = varint.value;
        } else {
            // Legacy transaction - marker is actually the first byte of input count
            // We need to reconstruct the VarInt
            if (marker < 0xFD) {
                input_count = marker;
            } else if (marker == 0xFD) {
                input_count = reader.readInt(u16, .little) catch return encode.Error.IoError;
            } else if (marker == 0xFE) {
                input_count = reader.readInt(u32, .little) catch return encode.Error.IoError;
            } else {
                input_count = reader.readInt(u64, .little) catch return encode.Error.IoError;
            }
        }

        // Inputs
        var inputs = std.ArrayList(TxIn).init(allocator);
        errdefer inputs.deinit();
        for (0..input_count) |_| {
            const txin = try TxIn.consensusDecode(option, reader);
            inputs.append(txin) catch return encode.Error.ParseFailed;
        }

        // Output count
        const output_varint = try VarInt.consensusDecode(option, reader);
        const output_count = output_varint.value;

        // Outputs
        var outputs = std.ArrayList(TxOut).init(allocator);
        errdefer outputs.deinit();
        for (0..output_count) |_| {
            const txout = try TxOut.consensusDecode(option, reader);
            outputs.append(txout) catch return encode.Error.ParseFailed;
        }

        // Witness data (if segwit)
        if (has_witness) {
            for (inputs.items) |*txin| {
                try txin.decodeWitness(option, reader);
            }
        }

        // Lock time
        const lock_time = try Decodable(u32).consensusDecode(option, reader);

        return Self{
            .version = version,
            .lock_time = lock_time,
            .input = inputs,
            .output = outputs,
            .allocator = allocator,
        };
    }
};

/// An input of a transaction. It contains the location of the previous
/// transaction's output that it claims and a signature that matches the
/// output's public key.
pub const TxIn = struct {
    /// The reference to the previous output that is being used as an input
    previousOutput: OutPoint,
    /// The script which pushes values on the stack which will cause
    /// the referenced output's script to accept
    scriptSig: Script,
    /// The sequence number, which suggests to miners which of two
    /// conflicting transactions should be preferred, or 0xFFFFFFFF
    /// to ignore this feature. This is generally never used since
    /// the miner behaviour cannot be enforced.
    sequence: u32,
    /// Witness data: an array of byte-arrays.
    /// Note that this field is *not* (de)serialized with the rest of the TxIn in
    /// Encodable/Decodable, as it is (de)serialized at the end of the full
    /// Transaction. It *is* (de)serialized with the rest of the TxIn in other
    /// (de)serialization routines.
    witness: ?[][]u8 = null,
    allocator: ?std.mem.Allocator = null,

    const Self = @This();

    /// Default sequence number (signals RBF disabled, locktime enabled)
    pub const SEQUENCE_FINAL: u32 = 0xFFFFFFFF;
    /// Sequence number for RBF (Replace-By-Fee)
    pub const SEQUENCE_RBF: u32 = 0xFFFFFFFD;

    pub fn init(prev_out: OutPoint, script_sig: Script, sequence: u32) Self {
        return Self{
            .previousOutput = prev_out,
            .scriptSig = script_sig,
            .sequence = sequence,
            .witness = null,
            .allocator = null,
        };
    }

    /// Create a default coinbase input
    pub fn coinbase(allocator: std.mem.Allocator, script_sig: Script) Self {
        return Self{
            .previousOutput = OutPoint.nullOutPoint(),
            .scriptSig = script_sig,
            .sequence = SEQUENCE_FINAL,
            .witness = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.scriptSig.deinit();
        if (self.witness) |w| {
            if (self.allocator) |alloc| {
                for (w) |item| {
                    alloc.free(item);
                }
                alloc.free(w);
            }
        }
    }

    /// Consensus encode the TxIn (without witness data)
    pub fn consensusEncode(self: *const Self, writer: anytype) encode.Error!usize {
        var len: usize = 0;

        // Previous output
        len += try self.previousOutput.consensusEncode(writer);

        // Script sig
        len += try self.scriptSig.consensusEncode(.{}, writer);

        // Sequence
        len += try Encodable(u32).init(self.sequence).consensusEncode(writer);

        return len;
    }

    /// Encode witness data
    pub fn encodeWitness(self: *const Self, writer: anytype) encode.Error!usize {
        var len: usize = 0;

        if (self.witness) |w| {
            // Number of witness stack items
            len += try Encodable(VarInt).init(VarInt.init(@intCast(w.len))).consensusEncode(writer);
            // Each witness stack item
            for (w) |item| {
                len += try Encodable(VarInt).init(VarInt.init(@intCast(item.len))).consensusEncode(writer);
                writer.writeAll(item) catch return encode.Error.IoError;
                len += item.len;
            }
        } else {
            // Empty witness
            len += try Encodable(VarInt).init(VarInt.init(0)).consensusEncode(writer);
        }

        return len;
    }

    /// Consensus decode a TxIn (without witness data)
    pub fn consensusDecode(option: DecoderOption, reader: Reader) encode.Error!Self {
        const allocator = option.allocator orelse return encode.Error.ParseFailed;

        // Previous output
        const prev_out = try OutPoint.consensusDecode(option, reader);

        // Script sig
        const script_sig = try Script.consensusDecode(option, reader);

        // Sequence
        const sequence = try Decodable(u32).consensusDecode(option, reader);

        return Self{
            .previousOutput = prev_out,
            .scriptSig = script_sig,
            .sequence = sequence,
            .witness = null,
            .allocator = allocator,
        };
    }

    /// Decode witness data
    pub fn decodeWitness(self: *Self, option: DecoderOption, reader: Reader) encode.Error!void {
        const allocator = option.allocator orelse return encode.Error.ParseFailed;

        const witness_count_varint = try VarInt.consensusDecode(option, reader);
        const witness_count = witness_count_varint.value;

        if (witness_count == 0) {
            self.witness = null;
            return;
        }

        var witness = allocator.alloc([]u8, witness_count) catch return encode.Error.ParseFailed;
        errdefer allocator.free(witness);

        for (0..witness_count) |i| {
            const item_len_varint = try VarInt.consensusDecode(option, reader);
            const item_len = item_len_varint.value;

            witness[i] = allocator.alloc(u8, item_len) catch return encode.Error.ParseFailed;
            _ = reader.readAll(witness[i]) catch return encode.Error.IoError;
        }

        self.witness = witness;
        self.allocator = allocator;
    }
};

/// An output of a transaction. It contains the public key that the next input
/// must be signed with to claim it.
pub const TxOut = struct {
    /// The value of the output, in satoshis
    value: u64,
    /// The script which must satisfy for the output to be spent
    script_pubkey: Script,

    const Self = @This();

    /// Maximum value for an output (21 million BTC in satoshis)
    pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

    pub fn default(allocator: std.mem.Allocator) Self {
        return Self{
            .value = 0xffffffffffffffff,
            .script_pubkey = Script.default(allocator),
        };
    }

    pub fn init(value: u64, script_pubkey: Script) Self {
        return Self{
            .value = value,
            .script_pubkey = script_pubkey,
        };
    }

    pub fn deinit(self: *Self) void {
        self.script_pubkey.deinit();
    }

    /// Consensus encode the TxOut
    pub fn consensusEncode(self: *const Self, writer: anytype) encode.Error!usize {
        var len: usize = 0;

        // Value
        len += try Encodable(u64).init(self.value).consensusEncode(writer);

        // Script pubkey
        len += try self.script_pubkey.consensusEncode(.{}, writer);

        return len;
    }

    /// Consensus decode a TxOut
    pub fn consensusDecode(option: DecoderOption, reader: Reader) encode.Error!Self {
        // Value
        const value = try Decodable(u64).consensusDecode(option, reader);

        // Script pubkey
        const script_pubkey = try Script.consensusDecode(option, reader);

        return Self{
            .value = value,
            .script_pubkey = script_pubkey,
        };
    }
};

/// A reference to a specific input in a transaction
pub const InPoint = struct {
    /// Pointer to the transaction (may be null)
    ptx: ?*Transaction,
    /// Index of the input
    n: i32,

    const Self = @This();

    pub fn init(tx: *Transaction, n: i32) Self {
        return Self{ .ptx = tx, .n = n };
    }

    pub fn setNull(self: *Self) void {
        self.ptx = null;
        self.n = -1;
    }

    pub fn isNull(self: *const Self) bool {
        return self.ptx == null and self.n == -1;
    }

    pub fn toString(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        if (self.isNull()) {
            return try allocator.dupe(u8, "InPoint(null, -1)");
        }
        return try std.fmt.allocPrint(allocator, "InPoint({*}, {d})", .{ self.ptx, self.n });
    }
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
    pub const Null = Self.initNull();

    fn initNull() Self {
        var null_txid: Txid = Txid.init();
        @memset(&null_txid.buf, 0);
        return Self{
            .txid = null_txid,
            .vout = std.math.maxInt(u32),
        };
    }

    /// Create a new [OutPoint]
    pub fn init(tx_id: Txid, vout: u32) Self {
        return Self{ .txid = tx_id, .vout = vout };
    }

    /// Creates a "null" `OutPoint`
    ///
    /// This value is used for coinbase transactions because they don't have
    /// any previous outputs.
    pub fn nullOutPoint() Self {
        return initNull();
    }

    /// Check if this is a null outpoint (used for coinbase)
    pub fn is_null(self: *const Self) bool {
        const null_point = Self.Null;
        return self.vout == null_point.vout and std.mem.eql(u8, &self.txid.buf, &null_point.txid.buf);
    }

    /// Convert to string representation
    pub fn toString(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        const hex_str = hash.hex(&self.txid.buf);
        // Reverse for display (Bitcoin displays txid in reverse byte order)
        var reversed: [64]u8 = undefined;
        var i: usize = 0;
        while (i < 32) : (i += 1) {
            reversed[i * 2] = hex_str[(31 - i) * 2];
            reversed[i * 2 + 1] = hex_str[(31 - i) * 2 + 1];
        }
        const str = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ reversed, self.vout });
        return str;
    }

    /// Parse an OutPoint from string format "txid:vout"
    pub fn fromString(str: []const u8) ParseOutPointError!Self {
        if (str.len > 75) { // 64 + 1 + 10
            return ParseOutPointError.TooLong;
        }

        // Find the colon separator
        const colon_pos = std.mem.indexOf(u8, str, ":") orelse return ParseOutPointError.Format;

        if (colon_pos != 64) {
            return ParseOutPointError.Txid;
        }

        // Parse txid (hex string)
        const txid_hex = str[0..64];
        var txid_bytes: [32]u8 = undefined;

        // Parse and reverse (Bitcoin displays txid in reverse)
        var i: usize = 0;
        while (i < 32) : (i += 1) {
            const high = hexCharToValue(txid_hex[(31 - i) * 2]) orelse return ParseOutPointError.Txid;
            const low = hexCharToValue(txid_hex[(31 - i) * 2 + 1]) orelse return ParseOutPointError.Txid;
            txid_bytes[i] = (high << 4) | low;
        }

        // Parse vout
        const vout_str = str[colon_pos + 1 ..];
        if (vout_str.len == 0) {
            return ParseOutPointError.Vout;
        }

        // Check for leading zeros (not canonical)
        if (vout_str.len > 1 and vout_str[0] == '0') {
            return ParseOutPointError.VoutNotCanonical;
        }

        // Check for + prefix (not canonical)
        if (vout_str[0] == '+') {
            return ParseOutPointError.VoutNotCanonical;
        }

        const vout = std.fmt.parseInt(u32, vout_str, 10) catch return ParseOutPointError.Vout;

        var result_txid: Txid = Txid.init();
        @memcpy(&result_txid.buf, &txid_bytes);

        return Self{
            .txid = result_txid,
            .vout = vout,
        };
    }

    /// Consensus encode the OutPoint
    pub fn consensusEncode(self: *const Self, writer: anytype) encode.Error!usize {
        var len: usize = 0;
        // Write txid bytes directly (32 bytes, little-endian)
        writer.writeAll(&self.txid.buf) catch return encode.Error.IoError;
        len += 32;
        // Write vout
        len += try Encodable(u32).init(self.vout).consensusEncode(writer);
        return len;
    }

    /// Consensus decode an OutPoint
    pub fn consensusDecode(_: DecoderOption, reader: Reader) encode.Error!Self {
        var txid_bytes: [32]u8 = undefined;
        _ = reader.readAll(&txid_bytes) catch return encode.Error.IoError;

        const vout = try Decodable(u32).consensusDecode(.{}, reader);

        var result_txid: Txid = Txid.init();
        @memcpy(&result_txid.buf, &txid_bytes);

        return Self{
            .txid = result_txid,
            .vout = vout,
        };
    }
};

/// Helper function to convert hex character to value
fn hexCharToValue(c: u8) ?u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    if (c >= 'A' and c <= 'F') return c - 'A' + 10;
    return null;
}

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

test "outpoint null" {
    const null_out = OutPoint.nullOutPoint();
    try std.testing.expect(null_out.is_null());

    var txid: Txid = Txid.init();
    @memset(&txid.buf, 0x01);
    const non_null = OutPoint.init(txid, 0);
    try std.testing.expect(!non_null.is_null());
}

test "outpoint from string" {
    // Valid outpoint
    const valid = "0000000000000000000000000000000000000000000000000000000000000001:0";
    const out = try OutPoint.fromString(valid);
    try std.testing.expectEqual(@as(u32, 0), out.vout);

    // Too long
    const too_long = "0" ** 80;
    try std.testing.expectError(ParseOutPointError.TooLong, OutPoint.fromString(too_long));

    // Missing colon
    const no_colon = "0000000000000000000000000000000000000000000000000000000000000001";
    try std.testing.expectError(ParseOutPointError.Format, OutPoint.fromString(no_colon));

    // Leading zero in vout (not canonical)
    const leading_zero = "0000000000000000000000000000000000000000000000000000000000000001:01";
    try std.testing.expectError(ParseOutPointError.VoutNotCanonical, OutPoint.fromString(leading_zero));
}

test "txin encode decode" {
    const allocator = std.testing.allocator;

    // Create a simple TxIn
    var txin = TxIn.init(
        OutPoint.nullOutPoint(),
        Script.new(allocator),
        TxIn.SEQUENCE_FINAL,
    );
    defer txin.deinit();

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    _ = try txin.consensusEncode(buffer.writer());

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    const decoded = try TxIn.consensusDecode(.{ .allocator = allocator }, stream.reader());
    var decoded_mut = decoded;
    defer decoded_mut.deinit();

    try std.testing.expectEqual(txin.sequence, decoded.sequence);
    try std.testing.expectEqual(txin.previousOutput.vout, decoded.previousOutput.vout);
}

test "txout encode decode" {
    const allocator = std.testing.allocator;

    // Create a simple TxOut
    var txout = TxOut.init(50000, Script.new(allocator));
    defer txout.deinit();

    // Encode
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    _ = try txout.consensusEncode(buffer.writer());

    // Decode
    var stream = std.io.fixedBufferStream(buffer.items);
    const decoded = try TxOut.consensusDecode(.{ .allocator = allocator }, stream.reader());
    var decoded_mut = decoded;
    defer decoded_mut.deinit();

    try std.testing.expectEqual(txout.value, decoded.value);
}

test "transaction init deinit" {
    const allocator = std.testing.allocator;

    var tx = Transaction.init(allocator);
    defer tx.deinit();

    try std.testing.expectEqual(@as(i32, 2), tx.version);
    try std.testing.expectEqual(@as(u32, 0), tx.lock_time);
    try std.testing.expectEqual(@as(usize, 0), tx.input.items.len);
    try std.testing.expectEqual(@as(usize, 0), tx.output.items.len);
}
