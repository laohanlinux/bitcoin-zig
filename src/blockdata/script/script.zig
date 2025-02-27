const std = @import("std");
const convert = @import("tools").usizeToU8;

pub const OpCodeType = enum(u16) {
    // push value
    OP_0 = 0,
    //OP_FALSE = 0,
    OP_PUSHDATA1 = 76,
    OP_PUSHDATA2,
    OP_PUSHDATA4,
    OP_1NEGATE,
    OP_RESERVED,
    OP_1,
    OP_TRUE = 82,
    OP_2,
    OP_3,
    OP_4,
    OP_5,
    OP_6,
    OP_7,
    OP_8,
    OP_9,
    OP_10,
    OP_11,
    OP_12,
    OP_13,
    OP_14,
    OP_15,
    OP_16,

    // control
    OP_NOP,
    OP_VER,
    OP_IF,
    OP_NOTIF,
    OP_VERIF,
    OP_VERNOTIF,
    OP_ELSE,
    OP_ENDIF,
    OP_VERIFY,
    OP_RETURN,

    // stack ops
    OP_TOALTSTACK,
    OP_FROMALTSTACK,
    OP_2DROP,
    OP_2DUP,
    OP_3DUP,
    OP_2OVER,
    OP_2ROT,
    OP_2SWAP,
    OP_IFDUP,
    OP_DEPTH,
    OP_DROP,
    OP_DUP,
    OP_NIP,
    OP_OVER,
    OP_PICK,
    OP_ROLL,
    OP_ROT,
    OP_SWAP,
    OP_TUCK,

    // splice ops
    OP_CAT,
    OP_SUBSTR,
    OP_LEFT,
    OP_RIGHT,
    OP_SIZE,

    // bit logic
    OP_INVERT,
    OP_AND,
    OP_OR,
    OP_XOR,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_RESERVED1,
    OP_RESERVED2,

    // numeric
    OP_1ADD,
    OP_1SUB,
    OP_2MUL,
    OP_2DIV,
    OP_NEGATE,
    OP_ABS,
    OP_NOT,
    OP_0NOTEQUAL,

    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_MOD,
    OP_LSHIFT,
    OP_RSHIFT,

    OP_BOOLAND,
    OP_BOOLOR,
    OP_NUMEQUAL,
    OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL,
    OP_LESSTHAN,
    OP_GREATERTHAN,
    OP_LESSTHANOREQUAL,
    OP_GREATERTHANOREQUAL,
    OP_MIN,
    OP_MAX,

    OP_WITHIN,

    // crypto
    OP_RIPEMD160,
    OP_SHA1,
    OP_SHA256,
    OP_HASH160,
    OP_HASH256,
    OP_CODESEPARATOR,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKMULTISIGVERIFY,

    // multi-byte opcodes
    OP_SINGLEBYTE_END = 0xF0,
    OP_DOUBLEBYTE_BEGIN = 0xF000,

    // template matching params
    OP_PUBKEY,
    OP_PUBKEYHASH,

    OP_INVALIDOPCODE = 0xFFFF,

    pub fn get_op_name(self: OpCodeType) []const u8 {
        switch (self) {
            .OP_0 => return "0",
            .OP_PUSHDATA1 => return "OP_PUSHDATA1",
            .OP_PUSHDATA2 => return "OP_PUSHDATA2",
            .OP_PUSHDATA4 => return "OP_PUSHDATA4",
            .OP_1NEGATE => return "-1",
            .OP_RESERVED => return "OP_RESERVED",
            .OP_1 => return "1",
            .OP_2 => return "2",
            .OP_3 => return "3",
            .OP_4 => return "4",
            .OP_5 => return "5",
            .OP_6 => return "6",
            .OP_7 => return "7",
            .OP_8 => return "8",
            .OP_9 => return "9",
            .OP_10 => return "10",
            .OP_11 => return "11",
            .OP_12 => return "12",
            .OP_13 => return "13",
            .OP_14 => return "14",
            .OP_15 => return "15",
            .OP_16 => return "16",
            // control
            .OP_NOP => return "OP_NOP",
            .OP_VER => return "OP_VER",
            .OP_IF => return "OP_IF",
            .OP_NOTIF => return "OP_NOTIF",
            .OP_VERIF => return "OP_VERIF",
            .OP_VERNOTIF => return "OP_VERNOTIF",
            .OP_ELSE => return "OP_ELSE",
            .OP_ENDIF => return "OP_ENDIF",
            .OP_VERIFY => return "OP_VERIFY",
            .OP_RETURN => return "OP_RETURN",
            // stack ops
            .OP_TOALTSTACK => return "OP_TOALTSTACK",
            .OP_FROMALTSTACK => return "OP_FROMALTSTACK",
            .OP_2DROP => return "OP_2DROP",
            .OP_2DUP => return "OP_2DUP",
            .OP_3DUP => return "OP_3DUP",
            .OP_2OVER => return "OP_2OVER",
            .OP_2ROT => return "OP_2ROT",
            .OP_2SWAP => return "OP_2SWAP",
            .OP_IFDUP => return "OP_IFDUP",
            .OP_DEPTH => return "OP_DEPTH",
            .OP_DROP => return "OP_DROP",
            .OP_DUP => return "OP_DUP",
            .OP_NIP => return "OP_NIP",
            .OP_OVER => return "OP_OVER",
            .OP_PICK => return "OP_PICK",
            .OP_ROLL => return "OP_ROLL",
            .OP_ROT => return "OP_ROT",
            .OP_SWAP => return "OP_SWAP",
            .OP_TUCK => return "OP_TUCK",
            // splice ops
            .OP_CAT => return "OP_CAT",
            .OP_SUBSTR => return "OP_SUBSTR",
            .OP_LEFT => return "OP_LEFT",
            .OP_RIGHT => return "OP_RIGHT",
            .OP_SIZE => return "OP_SIZE",

            // bit logic
            .OP_INVERT => return "OP_INVERT",
            .OP_AND => return "OP_AND",
            .OP_OR => return "OP_OR",
            .OP_XOR => return "OP_XOR",
            .OP_EQUAL => return "OP_EQUAL",
            .OP_EQUALVERIFY => return "OP_EQUALVERIFY",
            .OP_RESERVED1 => return "OP_RESERVED1",
            .OP_RESERVED2 => return "OP_RESERVED2",

            // numeric
            .OP_1ADD => return "OP_1ADD",
            .OP_1SUB => return "OP_1SUB",
            .OP_2MUL => return "OP_2MUL",
            .OP_2DIV => return "OP_2DIV",
            .OP_NEGATE => return "OP_NEGATE",
            .OP_ABS => return "OP_ABS",
            .OP_NOT => return "OP_NOT",
            .OP_0NOTEQUAL => return "OP_0NOTEQUAL",
            .OP_ADD => return "OP_ADD",
            .OP_SUB => return "OP_SUB",
            .OP_MUL => return "OP_MUL",
            .OP_DIV => return "OP_DIV",
            .OP_MOD => return "OP_MOD",
            .OP_LSHIFT => return "OP_LSHIFT",
            .OP_RSHIFT => return "OP_RSHIFT",
            .OP_BOOLAND => return "OP_BOOLAND",
            .OP_BOOLOR => return "OP_BOOLOR",
            .OP_NUMEQUAL => return "OP_NUMEQUAL",
            .OP_NUMEQUALVERIFY => return "OP_NUMEQUALVERIFY",
            .OP_NUMNOTEQUAL => return "OP_NUMNOTEQUAL",
            .OP_LESSTHAN => return "OP_LESSTHAN",
            .OP_GREATERTHAN => return "OP_GREATERTHAN",
            .OP_LESSTHANOREQUAL => return "OP_LESSTHANOREQUAL",
            .OP_GREATERTHANOREQUAL => return "OP_GREATERTHANOREQUAL",
            .OP_MIN => return "OP_MIN",
            .OP_MAX => return "OP_MAX",
            .OP_WITHIN => return "OP_WITHIN",
            // crypto
            .OP_RIPEMD160 => return "OP_RIPEMD160",
            .OP_SHA1 => return "OP_SHA1",
            .OP_SHA256 => return "OP_SHA256",
            .OP_HASH160 => return "OP_HASH160",
            .OP_HASH256 => return "OP_HASH256",
            .OP_CODESEPARATOR => return "OP_CODESEPARATOR",
            .OP_CHECKSIG => return "OP_CHECKSIG",
            .OP_CHECKSIGVERIFY => return "OP_CHECKSIGVERIFY",
            .OP_CHECKMULTISIG => return "OP_CHECKMULTISIG",
            .OP_CHECKMULTISIGVERIFY => return "OP_CHECKMULTISIGVERIFY",
            // multi-byte opcodes
            .OP_SINGLEBYTE_END => return "OP_SINGLEBYTE_END",
            .OP_DOUBLEBYTE_BEGIN => return "OP_DOUBLEBYTE_BEGIN",
            .OP_PUBKEY => return "OP_PUBKEY",
            .OP_PUBKEYHASH => return "OP_PUBKEYHASH",
            .OP_INVALIDOPCODE => return "OP_INVALIDOPCODE",
            else => return "UNKNOWN_OPCODE",
        }
    }

    pub fn to_u8(self: OpCodeType) u8 {
        return convert.usizeToU8(self.to_usize());
    }

    pub fn to_usize(self: OpCodeType) usize {
        return @intFromEnum(self);
    }
};

fn writeScriptInt(out: []u8, n: i64) u32 {
    var len: u32 = 0;
    if (n == 0) {
        return 0;
    }
    const neg: bool = n < 0;
    var abs: usize = if (neg) @intCast(n * -1) else @intCast(n);
    while (abs > 0xFF) : ({
        abs >>= 8;
        len += 1;
    }) {
        out[len] = @as(u8, @intCast(abs & 0xFF));
    }
    if (abs & 0x80 != 0) {
        out[len] = @as(u8, @intCast(abs));
        len += 1;
        out[len] = if (neg) 0x80 else 0;
        len += 1;
    } else {
        abs |= if (neg) 0x80 else 0;
        out[len] = @as(u8, @intCast(abs));
        len += 1;
    }
    return len;
}

pub const Script = struct {
    const Self = @This();
    vec: std.ArrayList(u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Self {
        const vec = std.ArrayList(u8).init(allocator);
        return .{ .vec = vec, .allocator = allocator };
    }

    pub fn default(allocator: std.mem.Allocator) Self {
        return .{ .vec = std.ArrayList(u8).init(allocator), .allocator = allocator };
    }

    pub fn deinit(self: Self) void {
        self.vec.deinit();
    }

    /// The length in bytes of the script
    pub fn len(self: *const Self) usize {
        return self.vec.items.len;
    }

    /// Whether the script is the empty script
    pub fn is_empty(self: *const Self) bool {
        return self.vec.items.len == 0;
    }
    /// Returns the script data
    pub fn as_bytes(self: *const Self) []const u8 {
        return self.vec.items;
    }

    /// Returns a copy of the script data
    pub fn to_bytes(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        const bytes = try allocator.alloc(u8, self.vec.items.len);
        @memcpy(bytes, self.vec.items);
        return bytes;
    }

    /// Convert the script into a byte vector
    pub fn into_bytes(self: Self) struct {
        bytes: []u8,
        allocator: std.mem.Allocator,
    } {
        return .{ .bytes = self.vec.items, .allocator = self.vec.allocator };
    }

    /// Convert the script into a string representation of the value
    pub fn value_string(self: *Self, vch: []const u8) []const u8 {
        if (vch.len <= 4) {
            const num = std.big.Int.fromSlice(std.big.IntSignedness.Signed, vch, std.big.LittleEndian, .{});
            return num.toStr();
        }
        _ = self;
        return "";
    }

    pub fn put_int(self: *Self, i: i64) void {
        _ = i;
        _ = self;
    }

    // pub fn push_slice(self: *Self, data: []u8) void {
    //     // cals data size
    //     // const data_len = data.len;
    // }

    pub fn put_code(self: *Self, code: OpCodeType) void {
        self.vec.append(code.to_u8());
    }

    /// Pushes the slice without reserving.
    pub fn push_slice_no_opt(self: *Self, data: []const u8) void {
        // Start with a PUSH opcode
        if (data.len < OpCodeType.OP_PUSHDATA1.to_usize()) {
            const len = @as(u8, @truncate(data.len));
            self.vec.append(len) catch unreachable;
        } else if (data.len < 0x100) {
            self.vec.append(OpCodeType.OP_PUSHDATA1.to_u8()) catch unreachable;
            self.vec.append(convert.usizeToU8(data.len)) catch unreachable;
        } else if (data.len < 0x10000) {
            self.vec.append(OpCodeType.OP_PUSHDATA2.to_u8()) catch unreachable;
            self.vec.append(convert.usizeToU8(data.len % 0x100)) catch unreachable;
            self.vec.append(convert.usizeToU8(data.len / 0x100)) catch unreachable;
        } else if (data.len < 0x1000000) {
            self.vec.append(OpCodeType.OP_PUSHDATA4.to_u8()) catch unreachable;
            self.vec.append(convert.usizeToU8(data.len % 0x100)) catch unreachable;
            self.vec.append(convert.usizeToU8((data.len / 0x100) % 100)) catch unreachable;
            self.vec.append(convert.usizeToU8((data.len / 0x10000) % 100)) catch unreachable;
            self.vec.append(convert.usizeToU8(data.len / 0x1000000)) catch unreachable;
        } else {
            @panic("tried to put a 4bn+ sized object into a script!");
        }
        self.vec.appendSlice(data) catch unreachable;
    }

    // Computes the sum of `len` and the length of an appropriate push opcode.
    // pub fn reserved_len_for_slice(len: usize) usize {
    //     const _len = switch (len) {
    //         0...0x4b => 1,
    //         0x4c...0xff => 2,
    //         else => 5, // we don't care about oversized, the other fn will panic anyway
    //     };
    //     return len + _len;
    // }
};

pub const ScriptBuilder = struct {
    const Self = @This();
    script: Script,
    opCode: ?OpCodeType,
    pub fn init() Self {
        const script = Script.init();
        return .{ .scritp = script, .opCode = null };
    }

    pub fn deinit(self: *Self) void {
        self.script.deinit();
    }

    pub fn push_int(self: *Self, i: i64) void {
        self.script.put_int(i);
    }

    pub fn len(self: *Self) u32 {
        return self.script.vec.items.len();
    }

    pub fn is_empty(self: *Self) bool {
        return self.len() == 0;
    }

    // pub fn push_slice(self: *Self, data: []u8) void {
    //     // self.script.pu
    // }

    pub fn push_opcode(self: *Self, opCode: OpCodeType) void {
        self.script.put_code(opCode);
        self.opCode.? = opCode;
    }
};

/// Data pushed by "push" opcodes.
///
/// "Push" opcodes are defined by Bitcoin Core as Op_PUSHBYTES_, OP_PUSHDATA, OP_PUSHNUM_, and
/// OP_RESERVED i.e., everything less than OP_PUSHNUM_16(0x60). (TODO: Add link to core code).
const Push = union(enum) {
    /// All the OP_PUSHBYTES_ and OP_PUSHDATA opcodes.
    data: []u8,
    /// All the OP_PUSHNUM_ opcodes (-1, 1, 2, .., 16)
    num: i8,
    /// OP_RESERVED
    Reserved: void,

    const Self = @This();

    pub fn to_string(self: Self) []const u8 {
        switch (self) {
            .data => return "the data type",
            .num => return "the num type",
            .Reserved => return "the reserved type",
        }
    }
};

test "Script OpTye" {
    const name = OpCodeType.OP_PUSHDATA1.get_op_name();
    std.debug.print("{s}\n", .{name});
    var buffer: [8]u8 = undefined;

    // Test positive number
    const len1 = writeScriptInt(buffer[0..], 899);

    std.debug.print("{d} {d}\n", .{ len1, buffer });

    var script = Script.init();
    script.put_int(899);
    const data: [:0]const u8 = "hello word!";
    script.push_slice_no_opt(data);

    const str = Push{ .num = 10 };
    std.debug.print("{s}\n", .{str.to_string()});
}
