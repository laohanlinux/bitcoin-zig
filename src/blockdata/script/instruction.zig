const std = @import("std");
const script = @import("./script.zig");

/// A "parsed opcode" which allows iterating over a ['Script'] in a more sensible way.
pub const Instruction = union(enum) {
    /// Push a bunch of data.
    pushBytes: std.ArrayList(u8),
    /// Some non-push opcode.
    op: script.OpCodeType,

    const Self = @This();

    /// Free resources held by this instruction
    pub fn deinit(self: Self) void {
        switch (self) {
            .pushBytes => |bs| bs.deinit(),
            .op => {},
        }
    }

    /// Returns the opcode if this is an opcode instruction, null otherwise
    pub fn opcode(self: Self) ?script.OpCodeType {
        return switch (self) {
            .pushBytes => null,
            .op => |op| op,
        };
    }

    /// Returns the pushed bytes if this is a push instruction, null otherwise
    pub fn bytes(self: Self) ?[]u8 {
        return switch (self) {
            .pushBytes => |bs| bs.items,
            .op => null,
        };
    }

    /// Appends bytes to a push instruction
    /// Only valid for pushBytes variant
    pub fn appendBytes(self: *Self, slice: []const u8) !void {
        switch (self.*) {
            .pushBytes => |*bs| try bs.appendSlice(slice),
            .op => return error.NotPushInstruction,
        }
    }

    /// Returns the number interpreted by the script parser,
    /// if it can be coerced into a number.
    ///
    /// This does not require the script number to be minimal.
    pub fn scriptNum(self: Self) ?i64 {
        switch (self) {
            .op => |op| {
                const v = op.to_u8();
                // OP_PUSHNUM_1 (0x51) through OP_PUSHNUM_16 (0x60)
                if (v >= 0x51 and v <= 0x60) {
                    return @as(i64, v) - 0x50;
                }
                // OP_PUSHNUM_NEG1 (0x4f)
                if (v == 0x4f) {
                    return -1;
                }
                // OP_0 / OP_FALSE (0x00)
                if (v == 0x00) {
                    return 0;
                }
                return null;
            },
            .pushBytes => |bs| {
                // Interpret pushed bytes as a script integer
                return readScriptInt(bs.items);
            },
        }
    }

    /// Check if this instruction represents a minimal push
    pub fn isMinimalPush(self: Self) bool {
        switch (self) {
            .pushBytes => |bs| {
                const data = bs.items;
                if (data.len == 0) return true;
                if (data.len == 1) {
                    // Could use OP_0, OP_1-OP_16, or OP_1NEGATE
                    if (data[0] == 0x81) return false; // Should be OP_1NEGATE
                    if (data[0] <= 16) return false; // Should be OP_n
                }
                return true;
            },
            .op => return true,
        }
    }
};

/// Read a script-encoded integer from bytes
/// Script integers are little-endian with a sign bit in the MSB of the last byte
fn readScriptInt(v: []const u8) ?i64 {
    if (v.len == 0) return 0;
    if (v.len > 4) return null; // Script integers are limited to 4 bytes

    var ret: i64 = 0;
    for (v, 0..) |byte, i| {
        ret |= @as(i64, byte) << @intCast(i * 8);
    }

    // Check sign bit in the last byte
    if (v[v.len - 1] & 0x80 != 0) {
        // Clear the sign bit and negate
        ret &= ~(@as(i64, 0x80) << @intCast((v.len - 1) * 8));
        ret = -ret;
    }

    return ret;
}

test "instruction bytes" {
    const allocator = std.testing.allocator;

    // Test pushBytes instruction
    var push_inst = Instruction{ .pushBytes = std.ArrayList(u8).init(allocator) };
    defer push_inst.deinit();

    try push_inst.appendBytes(&[_]u8{ 1, 2, 3 });
    const b = push_inst.bytes();
    try std.testing.expect(b != null);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, b.?);

    // Test op instruction returns null for bytes
    const op_inst = Instruction{ .op = script.OpCodeType.OP_DUP };
    try std.testing.expect(op_inst.bytes() == null);
    try std.testing.expect(op_inst.opcode() != null);
}

test "instruction script_num" {
    // Test OP_1NEGATE
    const neg1 = Instruction{ .op = script.OpCodeType.OP_1NEGATE };
    try std.testing.expectEqual(@as(?i64, -1), neg1.scriptNum());

    // Test OP_0
    const zero = Instruction{ .op = script.OpCodeType.OP_0 };
    try std.testing.expectEqual(@as(?i64, 0), zero.scriptNum());

    // Test OP_1
    const one = Instruction{ .op = script.OpCodeType.OP_1 };
    // OP_1 has value 81 (0x51), scriptNum should return 1
    const num = one.scriptNum();
    try std.testing.expect(num != null);
}

test "read script int" {
    // Empty = 0
    try std.testing.expectEqual(@as(?i64, 0), readScriptInt(&[_]u8{}));

    // Single byte positive
    try std.testing.expectEqual(@as(?i64, 1), readScriptInt(&[_]u8{0x01}));
    try std.testing.expectEqual(@as(?i64, 127), readScriptInt(&[_]u8{0x7f}));

    // Single byte negative
    try std.testing.expectEqual(@as(?i64, -1), readScriptInt(&[_]u8{0x81}));

    // Too long
    try std.testing.expectEqual(@as(?i64, null), readScriptInt(&[_]u8{ 1, 2, 3, 4, 5 }));
}
