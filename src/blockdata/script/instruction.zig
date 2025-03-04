const std = @import("std");
const allocator = @import("std.allocator");
const fmt = @import("std.fmt");
const script = @import("./script.zig");

/// A "parsed opcode" which will allows iterating over a ['Script'] in a more sensible way.
pub const Instruction = union(enum) {
    /// Push a bunch of data.
    pushBytes: std.ArrayList(u8),
    /// Some non-push opcode.
    op: script.OpCodeType,
    const Self = @This();

    pub fn deinit(self: Self) void {
        switch (self) {
            .pushBytes => |bs| bs.deinit(),
            .op => {},
        }
    }

    pub fn opcode(self: Self) ?script.OpCodeType {
        switch (self) {
            .pushBytes => return null,
            .op => |op| return op,
        }
    }

    pub fn bytes(self: Self) ?[]u8 {
        switch (self) {
            .pushBytes => |bs| return bs.items,
            .op => @panic(""),
        }
    }

    /// Returns the pushed bytes if the instruction is a data push.
    pub fn push_bytes(self: *Self, slice: []const u8) void {
        self.pushBytes.appendSlice(slice) catch unreachable;
    }

    /// Returns the number interpreted by the script parser.
    /// if it can be coerced into a number.
    ///
    /// This does no require the script number to be minial.
    pub fn script_num(self: Self) ?i64 {
        switch (self) {
            .op => |op| {
                const v = op.to_u8();
                switch (v) {
                    // OP_PUSHNUM1 ..= OP_PUSHNUM_16
                    0x51...0x60 => |num| return @intCast(num),
                    // O_PUSHNUM_NEG1
                    0x4f => return -1,
                    else => return null,
                }
            },
            .pushBytes => |bs| {
                _ = bs;
            },
        }
    }
};

test "Instruction parse" {}
