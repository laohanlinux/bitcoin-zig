// Zig Bitcoin Library
// Based on rust-bitcoin
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.

const std = @import("std");
const opcodes = @import("opcode.zig");
const hash_types = @import("../hash_types.zig");

/// Bitcoin script
pub const Script = struct {
    bytes: []const u8,
    allocator: ?std.mem.Allocator,

    /// Create a new empty script
    pub fn new(allocator: std.mem.Allocator) Script {
        return Script{
            .bytes = &[_]u8{},
            .allocator = allocator,
        };
    }

    /// Create script from existing bytes
    pub fn fromBytes(bytes: []const u8, allocator: std.mem.Allocator) !Script {
        const script_bytes = try allocator.dupe(u8, bytes);
        return Script{
            .bytes = script_bytes,
            .allocator = allocator,
        };
    }

    /// Length of the script in bytes
    pub fn len(self: Script) usize {
        return self.bytes.len;
    }

    /// Whether the script is empty
    pub fn isEmpty(self: Script) bool {
        return self.bytes.len == 0;
    }

    /// Get script data as bytes
    pub fn asBytes(self: Script) []const u8 {
        return self.bytes;
    }

    /// Return a copy of the script data
    pub fn toBytes(self: Script, allocator: std.mem.Allocator) ![]u8 {
        return try allocator.dupe(u8, self.bytes);
    }

    /// Compute the P2SH output corresponding to this redeem script
    pub fn toP2sh(self: Script, allocator: std.mem.Allocator) !Script {
        var builder = try Builder.new(allocator);
        defer builder.deinit();

        try builder.pushOpcode(opcodes.all.OP_HASH160);

        // Hash the script bytes using HASH160
        var hash = try hash_types.ScriptHash.hash(self.bytes);
        try builder.pushSlice(&hash);

        try builder.pushOpcode(opcodes.all.OP_EQUAL);

        return builder.intoScript();
    }

    /// Compute the P2WSH output corresponding to this witness script
    pub fn toV0P2wsh(self: Script, allocator: std.mem.Allocator) !Script {
        var builder = try Builder.new(allocator);
        defer builder.deinit();

        try builder.pushInt(0);

        // Hash the script using SHA256
        var hash = try hash_types.WScriptHash.hash(self.bytes);
        try builder.pushSlice(&hash);

        return builder.intoScript();
    }

    /// Checks whether a script pubkey is a p2sh output
    pub fn isP2sh(self: Script) bool {
        return self.bytes.len == 23 and
            self.bytes[0] == opcodes.all.OP_HASH160.into_u8() and
            self.bytes[1] == opcodes.all.OP_PUSHBYTES_20.into_u8() and
            self.bytes[22] == opcodes.all.OP_EQUAL.into_u8();
    }

    /// Checks whether a script pubkey is a p2pkh output
    pub fn isP2pkh(self: Script) bool {
        return self.bytes.len == 25 and
            self.bytes[0] == opcodes.all.OP_DUP.into_u8() and
            self.bytes[1] == opcodes.all.OP_HASH160.into_u8() and
            self.bytes[2] == opcodes.all.OP_PUSHBYTES_20.into_u8() and
            self.bytes[23] == opcodes.all.OP_EQUALVERIFY.into_u8() and
            self.bytes[24] == opcodes.all.OP_CHECKSIG.into_u8();
    }

    /// Checks whether a script pubkey is a p2pk output
    pub fn isP2pk(self: Script) bool {
        return (self.bytes.len == 67 and
            self.bytes[0] == opcodes.all.OP_PUSHBYTES_65.into_u8() and
            self.bytes[66] == opcodes.all.OP_CHECKSIG.into_u8()) or
            (self.bytes.len == 35 and
                self.bytes[0] == opcodes.all.OP_PUSHBYTES_33.into_u8() and
                self.bytes[34] == opcodes.all.OP_CHECKSIG.into_u8());
    }

    /// Checks whether a script pubkey is a Segregated Witness (segwit) program
    pub fn isWitnessProgram(self: Script) bool {
        const min_vernum: u8 = opcodes.all.OP_PUSHNUM_1.into_u8();
        const max_vernum: u8 = opcodes.all.OP_PUSHNUM_16.into_u8();

        return self.bytes.len >= 4 and
            self.bytes.len <= 42 and
            // Version 0 or PUSHNUM_1-PUSHNUM_16
            (self.bytes[0] == 0 or (self.bytes[0] >= min_vernum and self.bytes[0] <= max_vernum)) and
            // Second byte push opcode 2-40 bytes
            self.bytes[1] >= opcodes.all.OP_PUSHBYTES_2.into_u8() and
            self.bytes[1] <= opcodes.all.OP_PUSHBYTES_40.into_u8() and
            // Check that the rest of the script has the correct size
            self.bytes.len - 2 == self.bytes[1];
    }

    /// Checks whether a script pubkey is a p2wsh output
    pub fn isV0P2wsh(self: Script) bool {
        return self.bytes.len == 34 and
            self.bytes[0] == opcodes.all.OP_PUSHBYTES_0.into_u8() and
            self.bytes[1] == opcodes.all.OP_PUSHBYTES_32.into_u8();
    }

    /// Checks whether a script pubkey is a p2wpkh output
    pub fn isV0P2wpkh(self: Script) bool {
        return self.bytes.len == 22 and
            self.bytes[0] == opcodes.all.OP_PUSHBYTES_0.into_u8() and
            self.bytes[1] == opcodes.all.OP_PUSHBYTES_20.into_u8();
    }

    /// Check if this is an OP_RETURN output
    pub fn isOpReturn(self: Script) bool {
        return self.bytes.len > 0 and (opcodes.All.from_u8(self.bytes[0]) == opcodes.all.OP_RETURN);
    }

    /// Whether a script can be proven to have no satisfying input
    pub fn isProvablyUnspendable(self: Script) bool {
        return self.bytes.len > 0 and
            (opcodes.All.from_u8(self.bytes[0]).classify() == opcodes.Class.ReturnOp or
                opcodes.All.from_u8(self.bytes[0]).classify() == opcodes.Class.IllegalOp);
    }

    /// Iterate over the script in the form of Instructions
    pub fn instructions(self: Script) Instructions {
        return Instructions{
            .data = self.bytes,
            .enforce_minimal = false,
        };
    }

    /// Iterate over the script with enforced minimal pushes
    pub fn instructionsMinimal(self: Script) Instructions {
        return Instructions{
            .data = self.bytes,
            .enforce_minimal = true,
        };
    }

    /// Format the assembly representation of the script
    pub fn formatAsm(self: Script, writer: anytype) !void {
        var index: usize = 0;
        while (index < self.bytes.len) {
            const opcode = opcodes.All.from_u8(self.bytes[index]);
            index += 1;

            var data_len: usize = 0;
            if (opcode.classify() == .PushBytes) {
                if (opcode.classify()) |class| {
                    if (class == .PushBytes) {
                        const n = @as(usize, class.PushBytes);
                        data_len = n;
                    }
                }
            } else {
                if (opcode == opcodes.all.OP_PUSHDATA1) {
                    if (self.bytes.len < index + 1) {
                        try writer.writeAll("<unexpected end>");
                        break;
                    }
                    if (readUint(self.bytes[index..], 1)) |n| {
                        index += 1;
                        data_len = n;
                    } else |_| {
                        try writer.writeAll("<bad length>");
                        break;
                    }
                } else if (opcode == opcodes.all.OP_PUSHDATA2) {
                    if (self.bytes.len < index + 2) {
                        try writer.writeAll("<unexpected end>");
                        break;
                    }
                    if (readUint(self.bytes[index..], 2)) |n| {
                        index += 2;
                        data_len = n;
                    } else |_| {
                        try writer.writeAll("<bad length>");
                        break;
                    }
                } else if (opcode == opcodes.all.OP_PUSHDATA4) {
                    if (self.bytes.len < index + 4) {
                        try writer.writeAll("<unexpected end>");
                        break;
                    }
                    if (readUint(self.bytes[index..], 4)) |n| {
                        index += 4;
                        data_len = n;
                    } else |_| {
                        try writer.writeAll("<bad length>");
                        break;
                    }
                }
            }

            if (index > 1) try writer.writeAll(" ");

            // Write the opcode
            if (opcode == opcodes.all.OP_PUSHBYTES_0) {
                try writer.writeAll("OP_0");
            } else {
                var buf: [50]u8 = undefined;
                try writer.writeAll(try std.fmt.bufPrint(&buf, "{}", .{opcode}));
            }

            // Write any pushdata
            if (data_len > 0) {
                try writer.writeAll(" ");
                if (index + data_len <= self.bytes.len) {
                    var buf: [3]u8 = undefined;
                    for (self.bytes[index .. index + data_len]) |ch| {
                        try writer.writeAll(try std.fmt.bufPrint(&buf, "{x:0>2}", .{ch}));
                    }
                    index += data_len;
                } else {
                    try writer.writeAll("<push past end>");
                    break;
                }
            }
        }
    }

    /// Get the assembly representation of the script
    pub fn toAsm(self: Script, allocator: std.mem.Allocator) ![]u8 {
        var list = std.ArrayList(u8).init(allocator);
        defer list.deinit();

        try self.formatAsm(list.writer());
        return list.toOwnedSlice();
    }

    /// Free the memory if allocated
    pub fn deinit(self: *Script) void {
        if (self.bytes.len <= 0) return;
        if (self.allocator) |alloc| {
            alloc.free(self.bytes);
        }
    }
};

/// Possible script errors
pub const Error = error{
    /// Something did a non-minimal push
    NonMinimalPush,
    /// Opcode expected parameter but it was missing or truncated
    EarlyEndOfScript,
    /// Tried to read array as number when it was more than 4 bytes
    NumericOverflow,
    /// Could not find spent output
    UnknownSpentOutput,
    /// Serialization error
    SerializationError,
    /// Invalid scriptint
    InvalidScriptInt,
};

/// Type of script instruction
pub const Instruction = union(enum) {
    /// Push bytes
    PushBytes: []const u8,
    /// Non-push opcode
    Op: opcodes.All,
};

/// Iterator over script instructions
pub const Instructions = struct {
    data: []const u8,
    enforce_minimal: bool,
    index: usize = 0,

    /// Get the next instruction from the script
    pub fn next(self: *Instructions) ?Instruction {
        if (self.index >= self.data.len) {
            return null;
        }

        const opcode = opcodes.All.from_u8(self.data[self.index]);
        self.index += 1;

        switch (opcode.classify()) {
            .PushBytes => |n| {
                const n_usize = @as(usize, n);
                if (self.data.len < self.index + n_usize) {
                    self.index = self.data.len; // Stop iteration
                    return null;
                }

                if (self.enforce_minimal) {
                    if (n_usize == 1 and (self.data[self.index] == 0x81 or
                        (self.data[self.index] > 0 and self.data[self.index] <= 16)))
                    {
                        self.index = self.data.len; // Stop iteration
                        return null;
                    }
                }

                const result = Instruction{ .PushBytes = self.data[self.index .. self.index + n_usize] };
                self.index += n_usize;
                return result;
            },
            .Ordinary => |ord| {
                if (ord == .OP_PUSHDATA1) {
                    if (self.data.len < self.index + 1) {
                        self.index = self.data.len;
                        return null;
                    }

                    const n = self.data[self.index];
                    self.index += 1;

                    if (self.data.len < self.index + n) {
                        self.index = self.data.len;
                        return null;
                    }

                    if (self.enforce_minimal and n < 76) {
                        self.index = self.data.len;
                        return null;
                    }

                    const result = Instruction{ .PushBytes = self.data[self.index .. self.index + n] };
                    self.index += n;
                    return result;
                } else if (ord == .OP_PUSHDATA2) {
                    if (self.data.len < self.index + 2) {
                        self.index = self.data.len;
                        return null;
                    }

                    const n = @as(u16, self.data[self.index]) | (@as(u16, self.data[self.index + 1]) << 8);
                    self.index += 2;

                    if (self.data.len < self.index + n) {
                        self.index = self.data.len;
                        return null;
                    }

                    if (self.enforce_minimal and n < 0x100) {
                        self.index = self.data.len;
                        return null;
                    }

                    const result = Instruction{ .PushBytes = self.data[self.index .. self.index + n] };
                    self.index += n;
                    return result;
                } else if (ord == .OP_PUSHDATA4) {
                    if (self.data.len < self.index + 4) {
                        self.index = self.data.len;
                        return null;
                    }

                    const n = @as(u32, self.data[self.index]) |
                        (@as(u32, self.data[self.index + 1]) << 8) |
                        (@as(u32, self.data[self.index + 2]) << 16) |
                        (@as(u32, self.data[self.index + 3]) << 24);
                    self.index += 4;

                    if (self.data.len < self.index + n) {
                        self.index = self.data.len;
                        return null;
                    }

                    if (self.enforce_minimal and n < 0x10000) {
                        self.index = self.data.len;
                        return null;
                    }

                    const result = Instruction{ .PushBytes = self.data[self.index .. self.index + n] };
                    self.index += n;
                    return result;
                } else {
                    return Instruction{ .Op = opcode };
                }
            },
            else => {
                return Instruction{ .Op = opcode };
            },
        }
    }
};

/// Script builder
pub const Builder = struct {
    bytes: std.ArrayList(u8),
    last_op: ?opcodes.All,

    /// Create a new empty script builder
    pub fn new(allocator: std.mem.Allocator) !Builder {
        return Builder{
            .bytes = std.ArrayList(u8).init(allocator),
            .last_op = null,
        };
    }

    /// Length of the script
    pub fn len(self: Builder) usize {
        return self.bytes.items.len;
    }

    /// Whether the script is empty
    pub fn isEmpty(self: Builder) bool {
        return self.bytes.items.len == 0;
    }

    /// Adds instructions to push an integer onto the stack
    pub fn pushInt(self: *Builder, data: i64) !void {
        // Special-case -1, 1-16
        if (data == -1 or (data >= 1 and data <= 16)) {
            const op_val = @as(u8, @as(i64, opcodes.all.OP_PUSHNUM_1.into_u8()) + data - 1);
            const opcode = opcodes.All.from_u8(op_val);
            try self.pushOpcode(opcode);
        }
        // Special-case zero
        else if (data == 0) {
            try self.pushOpcode(opcodes.all.OP_FALSE);
        }
        // Otherwise encode as data
        else {
            try self.pushScriptint(data);
        }
    }

    /// Push integer using explicit encoding
    pub fn pushScriptint(self: *Builder, data: i64) !void {
        const int_bytes = try buildScriptint(data, self.bytes.allocator);
        defer self.bytes.allocator.free(int_bytes);
        try self.pushSlice(int_bytes);
    }

    /// Push arbitrary data onto the stack
    pub fn pushSlice(self: *Builder, data: []const u8) !void {
        // Start with PUSH opcode
        switch (data.len) {
            0...75 => try self.bytes.append(@as(u8, data.len)),
            76...255 => {
                try self.bytes.append(opcodes.Ordinary.OP_PUSHDATA1.into_u8());
                try self.bytes.append(@as(u8, data.len));
            },
            256...65535 => {
                try self.bytes.append(opcodes.Ordinary.OP_PUSHDATA2.into_u8());
                try self.bytes.append(@as(u8, data.len & 0xFF));
                try self.bytes.append(@as(u8, (data.len >> 8) & 0xFF));
            },
            65536...4294967295 => {
                try self.bytes.append(opcodes.Ordinary.OP_PUSHDATA4.into_u8());
                try self.bytes.append(@as(u8, data.len & 0xFF));
                try self.bytes.append(@as(u8, (data.len >> 8) & 0xFF));
                try self.bytes.append(@as(u8, (data.len >> 16) & 0xFF));
                try self.bytes.append(@as(u8, (data.len >> 24) & 0xFF));
            },
            else => @panic("tried to put a 4bn+ sized object into a script!"),
        }

        // Then push the raw bytes
        try self.bytes.appendSlice(data);
        self.last_op = null;
    }

    /// Adds a single opcode to the script
    pub fn pushOpcode(self: *Builder, data: opcodes.All) !void {
        try self.bytes.append(data.into_u8());
        self.last_op = data;
    }

    /// Adds OP_VERIFY unless the most-recently-added opcode has a VERIFY form
    pub fn pushVerify(self: *Builder) !void {
        if (self.last_op) |last| {
            if (last == opcodes.all.OP_EQUAL) {
                _ = self.bytes.pop();
                try self.pushOpcode(opcodes.all.OP_EQUALVERIFY);
            } else if (last == opcodes.all.OP_NUMEQUAL) {
                _ = self.bytes.pop();
                try self.pushOpcode(opcodes.all.OP_NUMEQUALVERIFY);
            } else if (last == opcodes.all.OP_CHECKSIG) {
                _ = self.bytes.pop();
                try self.pushOpcode(opcodes.all.OP_CHECKSIGVERIFY);
            } else if (last == opcodes.all.OP_CHECKMULTISIG) {
                _ = self.bytes.pop();
                try self.pushOpcode(opcodes.all.OP_CHECKMULTISIGVERIFY);
            } else {
                try self.pushOpcode(opcodes.all.OP_VERIFY);
            }
        } else {
            try self.pushOpcode(opcodes.all.OP_VERIFY);
        }
    }

    /// Convert the Builder into a Script
    pub fn intoScript(self: *Builder) !Script {
        const bytes = try self.bytes.toOwnedSlice();
        return Script{
            .bytes = bytes,
            .allocator = self.bytes.allocator,
        };
    }

    /// Free resources used by the builder
    pub fn deinit(self: *Builder) void {
        self.bytes.deinit();
    }
};

/// Helper to encode an integer in script format
fn buildScriptint(n: i64, allocator: std.mem.Allocator) ![]u8 {
    if (n == 0) return allocator.dupe(u8, &[_]u8{});

    const neg = n < 0;
    var abs: u64 = if (neg) @as(u64, -n) else @as(u64, n);

    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();

    while (abs > 0xFF) {
        try list.append(@as(u8, abs & 0xFF));
        abs >>= 8;
    }

    // If the number's value causes the sign bit to be set, we need an extra
    // byte to get the correct value and correct sign bit
    if (abs & 0x80 != 0) {
        try list.append(@as(u8, abs));
        try list.append(if (neg) 0x80 else 0x00);
    }
    // Otherwise we just set the sign bit ourselves
    else {
        abs |= if (neg) 0x80 else 0;
        try list.append(@as(u8, abs));
    }

    return list.toOwnedSlice();
}

/// Helper to decode an integer in script format
fn readScriptint(v: []const u8) !i64 {
    if (v.len == 0) return 0;
    if (v.len > 4) return Error.NumericOverflow;

    var ret: i64 = 0;
    var i: usize = 0;
    while (i < v.len) : (i += 1) {
        ret += @as(i64, v[i]) << @as(u6, i * 8);
    }

    // Check for sign bit
    if (v[v.len - 1] & 0x80 != 0) {
        ret &= (@as(i64, 1) << @as(u6, (v.len * 8 - 1))) - 1;
        ret = -ret;
    }

    return ret;
}

/// Read script boolean
fn readScriptbool(v: []const u8) bool {
    if (v.len == 0) return false;

    // Check if last byte is 0 or 0x80 and all previous bytes are 0
    if ((v[v.len - 1] == 0 or v[v.len - 1] == 0x80)) {
        var i: usize = 0;
        while (i < v.len - 1) : (i += 1) {
            if (v[i] != 0) return true;
        }
        return false;
    }

    return true;
}

/// Read a script-encoded unsigned integer
fn readUint(data: []const u8, size: usize) !usize {
    if (data.len < size) {
        return Error.EarlyEndOfScript;
    }

    var ret: usize = 0;
    var i: usize = 0;
    while (i < size) : (i += 1) {
        ret += @as(usize, data[i]) << @as(u6, i * 8);
    }

    return ret;
}

test "basic script tests" {
    const allocator = std.testing.allocator;

    // Create empty script
    var script = Script.new(allocator);
    defer script.deinit();
    try std.testing.expectEqual(script.len(), 0);
    try std.testing.expect(script.isEmpty());

    // // Create script from bytes
    const p2pkh_bytes = [_]u8{ 0x76, 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x88, 0xac };
    var p2pkh = try Script.fromBytes(&p2pkh_bytes, allocator);
    defer p2pkh.deinit();

    try std.testing.expect(p2pkh.isP2pkh());
    // try std.testing.expect(!p2pkh.isP2sh());
}

test "script builder" {
    const allocator = std.testing.allocator;

    var builder = try Builder.new(allocator);
    defer builder.deinit();

    // Push integers
    try builder.pushInt(0);
    try builder.pushInt(1);
    try builder.pushInt(-1);
    try builder.pushInt(16);
    try builder.pushInt(100);

    // Push opcodes
    try builder.pushOpcode(opcodes.all.OP_DUP);
    try builder.pushOpcode(opcodes.all.OP_HASH160);

    // Push data
    try builder.pushSlice(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });

    // Create script
    var script = try builder.intoScript();
    defer script.deinit();

    try std.testing.expectEqual(script.len(), 11);
}

test "script int encoding" {
    const allocator = std.testing.allocator;

    const cases = [_]i64{ 0, 1, -1, 127, -127, 128, -128, 255, 256, -256, 1000, -1000 };

    for (cases) |n| {
        const encoded = try buildScriptint(n, allocator);
        defer allocator.free(encoded);

        const decoded = try readScriptint(encoded);
        try std.testing.expectEqual(n, decoded);
    }
}
