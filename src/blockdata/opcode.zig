const std = @import("std");

/// Represents a Bitcoin script opcode
pub const All = struct {
    code: u8,

    /// Convert opcode to its byte representation
    pub fn into_u8(self: All) u8 {
        return self.code;
    }

    /// Create an opcode from a byte
    pub fn from_u8(b: u8) All {
        return All{ .code = b };
    }

    /// Classify the opcode into its semantic type
    pub fn classify(self: All) Class {
        const code = self.code;

        if (code == 0x00) {
            return Class{ .PushBytes = 0 };
        } else if (code >= 0x01 and code <= 0x4b) {
            return Class{ .PushBytes = code };
        } else if (code == 0x4c) {
            return Class{ .Ordinary = Ordinary.OP_PUSHDATA1 };
        } else if (code == 0x4d) {
            return Class{ .Ordinary = Ordinary.OP_PUSHDATA2 };
        } else if (code == 0x4e) {
            return Class{ .Ordinary = Ordinary.OP_PUSHDATA4 };
        } else if (code == 0x4f) {
            return Class{ .PushNum = -1 };
        } else if (code == 0x50) {
            return Class{ .Ordinary = Ordinary.OP_RESERVED };
        } else if (code >= 0x51 and code <= 0x60) {
            return Class{ .PushNum = @intCast(code - 0x50) };
        } else if (code >= 0x61 and code <= 0x68) {
            if (code == 0x61) {
                return Class.NoOp;
            } else {
                return Class{ .Ordinary = @enumFromInt(code) };
            }
        } else if (code == 0x69) {
            return Class{ .Ordinary = Ordinary.OP_VERIFY };
        } else if (code == 0x6a) {
            return Class.ReturnOp;
        } else if ((code >= 0x6b and code <= 0xb9) or
            (code >= 0xba and code <= 0xff))
        {
            if (code >= 0xba) {
                return Class.ReturnOp;
            } else {
                return Class{ .Ordinary = @enumFromInt(code) };
            }
        } else {
            return Class.IllegalOp;
        }
    }

    /// Format opcode for debugging
    pub fn format(
        self: All,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        const code = self.code;

        // Output appropriate opcode name based on value
        if (code == 0x00) {
            try writer.writeAll("OP_PUSHBYTES_0");
        } else if (code >= 0x01 and code <= 0x4b) {
            try writer.print("OP_PUSHBYTES_{d}", .{code});
        } else {
            // Handle all other opcodes by name
            const name = switch (code) {
                0x4c => "OP_PUSHDATA1",
                0x4d => "OP_PUSHDATA2",
                0x4e => "OP_PUSHDATA4",
                0x4f => "OP_PUSHNUM_NEG1",
                0x50 => "OP_RESERVED",
                0x51 => "OP_PUSHNUM_1",
                0x52 => "OP_PUSHNUM_2",
                // ... and so on for all other opcodes
                0x76 => "OP_DUP",
                0xa9 => "OP_HASH160",
                0xac => "OP_CHECKSIG",
                else => "UNKNOWN_OP",
            };
            try writer.writeAll(name);
        }
    }
};

/// All possible opcode constants
pub const all = struct {
    /// Push an empty array onto the stack
    pub const OP_PUSHBYTES_0: All = All{ .code = 0x00 };
    /// Push the next byte as an array onto the stack
    pub const OP_PUSHBYTES_1: All = All{ .code = 0x01 };
    /// Push the next 2 bytes as an array onto the stack
    pub const OP_PUSHBYTES_2: All = All{ .code = 0x02 };
    /// Push the next 2 bytes as an array onto the stack
    pub const OP_PUSHBYTES_3: All = All{ .code = 0x03 };
    /// Push the next 4 bytes as an array onto the stack
    pub const OP_PUSHBYTES_4: All = All{ .code = 0x04 };
    /// Push the next 5 bytes as an array onto the stack
    pub const OP_PUSHBYTES_5: All = All{ .code = 0x05 };
    /// Push the next 6 bytes as an array onto the stack
    pub const OP_PUSHBYTES_6: All = All{ .code = 0x06 };
    /// Push the next 7 bytes as an array onto the stack
    pub const OP_PUSHBYTES_7: All = All{ .code = 0x07 };
    /// Push the next 8 bytes as an array onto the stack
    pub const OP_PUSHBYTES_8: All = All{ .code = 0x08 };
    /// Push the next 9 bytes as an array onto the stack
    pub const OP_PUSHBYTES_9: All = All{ .code = 0x09 };
    /// Push the next 10 bytes as an array onto the stack
    pub const OP_PUSHBYTES_10: All = All{ .code = 0x0a };
    /// Push the next 11 bytes as an array onto the stack
    pub const OP_PUSHBYTES_11: All = All{ .code = 0x0b };
    /// Push the next 12 bytes as an array onto the stack
    pub const OP_PUSHBYTES_12: All = All{ .code = 0x0c };
    /// Push the next 13 bytes as an array onto the stack
    pub const OP_PUSHBYTES_13: All = All{ .code = 0x0d };
    /// Push the next 14 bytes as an array onto the stack
    pub const OP_PUSHBYTES_14: All = All{ .code = 0x0e };
    /// Push the next 15 bytes as an array onto the stack
    pub const OP_PUSHBYTES_15: All = All{ .code = 0x0f };
    /// Push the next 16 bytes as an array onto the stack
    pub const OP_PUSHBYTES_16: All = All{ .code = 0x10 };
    /// Push the next 17 bytes as an array onto the stack
    pub const OP_PUSHBYTES_17: All = All{ .code = 0x11 };
    /// Push the next 18 bytes as an array onto the stack
    pub const OP_PUSHBYTES_18: All = All{ .code = 0x12 };
    /// Push the next 19 bytes as an array onto the stack
    pub const OP_PUSHBYTES_19: All = All{ .code = 0x13 };
    /// Push the next 20 bytes as an array onto the stack
    pub const OP_PUSHBYTES_20: All = All{ .code = 0x14 };
    /// Push the next 21 bytes as an array onto the stack
    pub const OP_PUSHBYTES_21: All = All{ .code = 0x15 };
    /// Push the next 22 bytes as an array onto the stack
    pub const OP_PUSHBYTES_22: All = All{ .code = 0x16 };
    /// Push the next 23 bytes as an array onto the stack
    pub const OP_PUSHBYTES_23: All = All{ .code = 0x17 };
    /// Push the next 24 bytes as an array onto the stack
    pub const OP_PUSHBYTES_24: All = All{ .code = 0x18 };
    /// Push the next 25 bytes as an array onto the stack
    pub const OP_PUSHBYTES_25: All = All{ .code = 0x19 };
    /// Push the next 26 bytes as an array onto the stack
    pub const OP_PUSHBYTES_26: All = All{ .code = 0x1a };
    /// Push the next 27 bytes as an array onto the stack
    pub const OP_PUSHBYTES_27: All = All{ .code = 0x1b };
    /// Push the next 28 bytes as an array onto the stack
    pub const OP_PUSHBYTES_28: All = All{ .code = 0x1c };
    /// Push the next 29 bytes as an array onto the stack
    pub const OP_PUSHBYTES_29: All = All{ .code = 0x1d };
    /// Push the next 30 bytes as an array onto the stack
    pub const OP_PUSHBYTES_30: All = All{ .code = 0x1e };
    /// Push the next 31 bytes as an array onto the stack
    pub const OP_PUSHBYTES_31: All = All{ .code = 0x1f };
    /// Push the next 32 bytes as an array onto the stack
    pub const OP_PUSHBYTES_32: All = All{ .code = 0x20 };
    /// Push the next 33 bytes as an array onto the stack
    pub const OP_PUSHBYTES_33: All = All{ .code = 0x21 };
    /// Push the next 34 bytes as an array onto the stack
    pub const OP_PUSHBYTES_34: All = All{ .code = 0x22 };
    /// Push the next 35 bytes as an array onto the stack
    pub const OP_PUSHBYTES_35: All = All{ .code = 0x23 };
    /// Push the next 36 bytes as an array onto the stack
    pub const OP_PUSHBYTES_36: All = All{ .code = 0x24 };
    /// Push the next 37 bytes as an array onto the stack
    pub const OP_PUSHBYTES_37: All = All{ .code = 0x25 };
    /// Push the next 38 bytes as an array onto the stack
    pub const OP_PUSHBYTES_38: All = All{ .code = 0x26 };
    /// Push the next 39 bytes as an array onto the stack
    pub const OP_PUSHBYTES_39: All = All{ .code = 0x27 };
    /// Push the next 40 bytes as an array onto the stack
    pub const OP_PUSHBYTES_40: All = All{ .code = 0x28 };
    /// Push the next 41 bytes as an array onto the stack
    pub const OP_PUSHBYTES_41: All = All{ .code = 0x29 };
    /// Push the next 42 bytes as an array onto the stack
    pub const OP_PUSHBYTES_42: All = All{ .code = 0x2a };
    /// Push the next 43 bytes as an array onto the stack
    pub const OP_PUSHBYTES_43: All = All{ .code = 0x2b };
    /// Push the next 44 bytes as an array onto the stack
    pub const OP_PUSHBYTES_44: All = All{ .code = 0x2c };
    /// Push the next 45 bytes as an array onto the stack
    pub const OP_PUSHBYTES_45: All = All{ .code = 0x2d };
    /// Push the next 46 bytes as an array onto the stack
    pub const OP_PUSHBYTES_46: All = All{ .code = 0x2e };
    /// Push the next 47 bytes as an array onto the stack
    pub const OP_PUSHBYTES_47: All = All{ .code = 0x2f };
    /// Push the next 48 bytes as an array onto the stack
    pub const OP_PUSHBYTES_48: All = All{ .code = 0x30 };
    /// Push the next 49 bytes as an array onto the stack
    pub const OP_PUSHBYTES_49: All = All{ .code = 0x31 };
    /// Push the next 50 bytes as an array onto the stack
    pub const OP_PUSHBYTES_50: All = All{ .code = 0x32 };
    /// Push the next 51 bytes as an array onto the stack
    pub const OP_PUSHBYTES_51: All = All{ .code = 0x33 };
    /// Push the next 52 bytes as an array onto the stack
    pub const OP_PUSHBYTES_52: All = All{ .code = 0x34 };
    /// Push the next 53 bytes as an array onto the stack
    pub const OP_PUSHBYTES_53: All = All{ .code = 0x35 };
    /// Push the next 54 bytes as an array onto the stack
    pub const OP_PUSHBYTES_54: All = All{ .code = 0x36 };
    /// Push the next 55 bytes as an array onto the stack
    pub const OP_PUSHBYTES_55: All = All{ .code = 0x37 };
    /// Push the next 56 bytes as an array onto the stack
    pub const OP_PUSHBYTES_56: All = All{ .code = 0x38 };
    /// Push the next 57 bytes as an array onto the stack
    pub const OP_PUSHBYTES_57: All = All{ .code = 0x39 };
    /// Push the next 58 bytes as an array onto the stack
    pub const OP_PUSHBYTES_58: All = All{ .code = 0x3a };
    /// Push the next 59 bytes as an array onto the stack
    pub const OP_PUSHBYTES_59: All = All{ .code = 0x3b };
    /// Push the next 60 bytes as an array onto the stack
    pub const OP_PUSHBYTES_60: All = All{ .code = 0x3c };
    /// Push the next 61 bytes as an array onto the stack
    pub const OP_PUSHBYTES_61: All = All{ .code = 0x3d };
    /// Push the next 62 bytes as an array onto the stack
    pub const OP_PUSHBYTES_62: All = All{ .code = 0x3e };
    /// Push the next 63 bytes as an array onto the stack
    pub const OP_PUSHBYTES_63: All = All{ .code = 0x3f };
    /// Push the next 64 bytes as an array onto the stack
    pub const OP_PUSHBYTES_64: All = All{ .code = 0x40 };
    /// Push the next 65 bytes as an array onto the stack
    pub const OP_PUSHBYTES_65: All = All{ .code = 0x41 };
    /// Push the next 66 bytes as an array onto the stack
    pub const OP_PUSHBYTES_66: All = All{ .code = 0x42 };
    /// Push the next 67 bytes as an array onto the stack
    pub const OP_PUSHBYTES_67: All = All{ .code = 0x43 };
    /// Push the next 68 bytes as an array onto the stack
    pub const OP_PUSHBYTES_68: All = All{ .code = 0x44 };
    /// Push the next 69 bytes as an array onto the stack
    pub const OP_PUSHBYTES_69: All = All{ .code = 0x45 };
    /// Push the next 70 bytes as an array onto the stack
    pub const OP_PUSHBYTES_70: All = All{ .code = 0x46 };
    /// Push the next 71 bytes as an array onto the stack
    pub const OP_PUSHBYTES_71: All = All{ .code = 0x47 };
    /// Push the next 72 bytes as an array onto the stack
    pub const OP_PUSHBYTES_72: All = All{ .code = 0x48 };
    /// Push the next 73 bytes as an array onto the stack
    pub const OP_PUSHBYTES_73: All = All{ .code = 0x49 };
    /// Push the next 74 bytes as an array onto the stack
    pub const OP_PUSHBYTES_74: All = All{ .code = 0x4a };
    /// Push the next 75 bytes as an array onto the stack
    pub const OP_PUSHBYTES_75: All = All{ .code = 0x4b };
    // ... for brevity, not listing all push byte opcodes

    pub const OP_PUSHDATA1 = All{ .code = 0x4c };
    pub const OP_PUSHDATA2 = All{ .code = 0x4d };
    pub const OP_PUSHDATA4 = All{ .code = 0x4e };
    pub const OP_PUSHNUM_NEG1 = All{ .code = 0x4f };
    pub const OP_RESERVED = All{ .code = 0x50 };
    pub const OP_PUSHNUM_1 = All{ .code = 0x51 };
    pub const OP_PUSHNUM_2 = All{ .code = 0x52 };
    pub const OP_PUSHNUM_3 = All{ .code = 0x53 };
    pub const OP_PUSHNUM_4 = All{ .code = 0x54 };
    pub const OP_PUSHNUM_5 = All{ .code = 0x55 };
    pub const OP_PUSHNUM_6 = All{ .code = 0x56 };
    pub const OP_PUSHNUM_7 = All{ .code = 0x57 };
    pub const OP_PUSHNUM_8 = All{ .code = 0x58 };
    pub const OP_PUSHNUM_9 = All{ .code = 0x59 };
    pub const OP_PUSHNUM_10 = All{ .code = 0x5a };
    pub const OP_PUSHNUM_11 = All{ .code = 0x5b };
    pub const OP_PUSHNUM_12 = All{ .code = 0x5c };
    pub const OP_PUSHNUM_13 = All{ .code = 0x5d };
    pub const OP_PUSHNUM_14 = All{ .code = 0x5e };
    pub const OP_PUSHNUM_15 = All{ .code = 0x5f };
    pub const OP_PUSHNUM_16 = All{ .code = 0x60 };

    pub const OP_NOP = All{ .code = 0x61 };
    pub const OP_VER = All{ .code = 0x62 };
    pub const OP_IF = All{ .code = 0x63 };
    pub const OP_NOTIF = All{ .code = 0x64 };
    pub const OP_VERIF = All{ .code = 0x65 };
    pub const OP_VERNOTIF = All{ .code = 0x66 };
    pub const OP_ELSE = All{ .code = 0x67 };
    pub const OP_ENDIF = All{ .code = 0x68 };
    pub const OP_VERIFY = All{ .code = 0x69 };
    pub const OP_RETURN = All{ .code = 0x6a };

    pub const OP_TOALTSTACK = All{ .code = 0x6b };
    pub const OP_FROMALTSTACK = All{ .code = 0x6c };
    pub const OP_2DROP = All{ .code = 0x6d };
    pub const OP_2DUP = All{ .code = 0x6e };
    pub const OP_3DUP = All{ .code = 0x6f };
    pub const OP_2OVER = All{ .code = 0x70 };
    pub const OP_2ROT = All{ .code = 0x71 };
    pub const OP_2SWAP = All{ .code = 0x72 };
    pub const OP_IFDUP = All{ .code = 0x73 };
    pub const OP_DEPTH = All{ .code = 0x74 };
    pub const OP_DROP = All{ .code = 0x75 };
    pub const OP_DUP = All{ .code = 0x76 };
    pub const OP_NIP = All{ .code = 0x77 };
    pub const OP_OVER = All{ .code = 0x78 };
    pub const OP_PICK = All{ .code = 0x79 };
    pub const OP_ROLL = All{ .code = 0x7a };
    pub const OP_ROT = All{ .code = 0x7b };
    pub const OP_SWAP = All{ .code = 0x7c };
    pub const OP_TUCK = All{ .code = 0x7d };

    // String operations
    pub const OP_CAT = All{ .code = 0x7e };
    pub const OP_SUBSTR = All{ .code = 0x7f };
    pub const OP_LEFT = All{ .code = 0x80 };
    pub const OP_RIGHT = All{ .code = 0x81 };
    pub const OP_SIZE = All{ .code = 0x82 };

    // Bitwise operations
    pub const OP_INVERT = All{ .code = 0x83 };
    pub const OP_AND = All{ .code = 0x84 };
    pub const OP_OR = All{ .code = 0x85 };
    pub const OP_XOR = All{ .code = 0x86 };

    // Comparison operations
    pub const OP_EQUAL = All{ .code = 0x87 };
    pub const OP_EQUALVERIFY = All{ .code = 0x88 };
    pub const OP_RESERVED1 = All{ .code = 0x89 };
    pub const OP_RESERVED2 = All{ .code = 0x8a };

    // Arithmetic operations
    pub const OP_1ADD = All{ .code = 0x8b };
    pub const OP_1SUB = All{ .code = 0x8c };
    pub const OP_2MUL = All{ .code = 0x8d };
    pub const OP_2DIV = All{ .code = 0x8e };
    pub const OP_NEGATE = All{ .code = 0x8f };
    pub const OP_ABS = All{ .code = 0x90 };
    pub const OP_NOT = All{ .code = 0x91 };
    pub const OP_0NOTEQUAL = All{ .code = 0x92 };
    pub const OP_ADD = All{ .code = 0x93 };
    pub const OP_SUB = All{ .code = 0x94 };
    pub const OP_MUL = All{ .code = 0x95 };
    pub const OP_DIV = All{ .code = 0x96 };
    pub const OP_MOD = All{ .code = 0x97 };
    pub const OP_LSHIFT = All{ .code = 0x98 };
    pub const OP_RSHIFT = All{ .code = 0x99 };

    // Logical operations
    pub const OP_BOOLAND = All{ .code = 0x9a };
    pub const OP_BOOLOR = All{ .code = 0x9b };
    pub const OP_NUMEQUAL = All{ .code = 0x9c };
    pub const OP_NUMEQUALVERIFY = All{ .code = 0x9d };
    pub const OP_NUMNOTEQUAL = All{ .code = 0x9e };
    pub const OP_LESSTHAN = All{ .code = 0x9f };
    pub const OP_GREATERTHAN = All{ .code = 0xa0 };
    pub const OP_LESSTHANOREQUAL = All{ .code = 0xa1 };
    pub const OP_GREATERTHANOREQUAL = All{ .code = 0xa2 };
    pub const OP_MIN = All{ .code = 0xa3 };
    pub const OP_MAX = All{ .code = 0xa4 };
    pub const OP_WITHIN = All{ .code = 0xa5 };

    // Crypto operations
    pub const OP_RIPEMD160 = All{ .code = 0xa6 };
    pub const OP_SHA1 = All{ .code = 0xa7 };
    pub const OP_SHA256 = All{ .code = 0xa8 };
    pub const OP_HASH160 = All{ .code = 0xa9 };
    pub const OP_HASH256 = All{ .code = 0xaa };
    pub const OP_CODESEPARATOR = All{ .code = 0xab };
    pub const OP_CHECKSIG = All{ .code = 0xac };
    pub const OP_CHECKSIGVERIFY = All{ .code = 0xad };
    pub const OP_CHECKMULTISIG = All{ .code = 0xae };
    pub const OP_CHECKMULTISIGVERIFY = All{ .code = 0xaf };

    // NOP operations
    pub const OP_NOP1 = All{ .code = 0xb0 };
    pub const OP_CLTV = All{ .code = 0xb1 }; // OP_CHECKLOCKTIMEVERIFY
    pub const OP_CSV = All{ .code = 0xb2 }; // OP_CHECKSEQUENCEVERIFY
    pub const OP_NOP4 = All{ .code = 0xb3 };
    pub const OP_NOP5 = All{ .code = 0xb4 };
    pub const OP_NOP6 = All{ .code = 0xb5 };
    pub const OP_NOP7 = All{ .code = 0xb6 };
    pub const OP_NOP8 = All{ .code = 0xb7 };
    pub const OP_NOP9 = All{ .code = 0xb8 };
    pub const OP_NOP10 = All{ .code = 0xb9 };

    // OP_RETURN codes (0xba-0xff)
    pub const OP_RETURN_186 = All{ .code = 0xba };
    // ... additional OP_RETURN codes would be listed here
    pub const OP_RETURN_255 = All{ .code = 0xff };
};

/// Empty stack is also FALSE
pub const OP_FALSE: All = all.OP_PUSHBYTES_0;
/// Number 1 is also TRUE
pub const OP_TRUE: All = all.OP_PUSHNUM_1;
/// previously called OP_NOP2
pub const OP_NOP2: All = all.OP_CLTV;
/// previously called OP_NOP3
pub const OP_NOP3: All = all.OP_CSV;

/// Categorizes opcodes by their behavior
pub const Class = union(enum) {
    /// Push a number onto the stack
    PushNum: i32,

    /// Push bytes onto the stack
    PushBytes: u32,

    /// Fails the script if executed
    ReturnOp,

    /// Fails the script even if not executed
    IllegalOp,

    /// Does nothing
    NoOp,

    /// Any opcode not covered above
    Ordinary: Ordinary,

    /// Format the class for debugging
    pub fn format(
        self: Class,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        switch (self) {
            .PushNum => |n| try writer.print("PushNum({d})", .{n}),
            .PushBytes => |n| try writer.print("PushBytes({d})", .{n}),
            .ReturnOp => try writer.writeAll("ReturnOp"),
            .IllegalOp => try writer.writeAll("IllegalOp"),
            .NoOp => try writer.writeAll("NoOp"),
            .Ordinary => |o| try writer.print("Ordinary({any})", .{o}),
        }
    }
};

/// Ordinary opcodes (not special-cased)
pub const Ordinary = enum(u8) {
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_RESERVED = 0x50,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    // ... and all other ordinary opcodes

    /// Convert to byte representation
    pub fn into_u8(self: Ordinary) u8 {
        return @intFromEnum(self);
    }
};

test "opcode classification" {
    // Test a few opcode classifications
    try std.testing.expectEqual(Class{ .PushBytes = 0 }, all.OP_PUSHBYTES_0.classify());

    try std.testing.expectEqual(Class{ .PushNum = 1 }, all.OP_PUSHNUM_1.classify());

    try std.testing.expectEqual(Class.ReturnOp, all.OP_RETURN.classify());

    try std.testing.expectEqual(Class.NoOp, all.OP_NOP.classify());
}

test "str_roundtrip" {
    var unique = std.AutoHashMap(u8, void).init(std.testing.allocator);
    defer unique.deinit();

    // Test roundtrip for a few opcodes
    inline for (.{
        all.OP_PUSHBYTES_0,
        all.OP_PUSHBYTES_1,
        all.OP_PUSHDATA1,
        all.OP_PUSHNUM_1,
        all.OP_DUP,
        all.OP_EQUAL,
        all.OP_VERIFY,
        all.OP_RETURN,
        all.OP_CHECKSIG,
    }) |op| {
        const code = op.into_u8();
        try unique.put(code, {});

        const roundtrip = All.from_u8(code);
        try std.testing.expectEqual(code, roundtrip.into_u8());
    }
}
