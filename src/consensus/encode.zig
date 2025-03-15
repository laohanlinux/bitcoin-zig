// Zig Bitcoin Library
// Translated from Rust Bitcoin Library
// Original written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

const std = @import("std");
const io = std.io;
const fmt = std.fmt;
const mem = std.mem;
const math = std.math;
const testing = std.testing;

const hash = @import("../hashes/hash_engine.zig");
const Sha256D = hash.HashEngine(.sha256d);
const hex = hash.hex;

/// 编码错误
pub const Error = error{
    /// I/O 错误
    IoError,
    /// PSBT 相关错误
    PsbtError,
    /// 网络魔术值不符合预期
    UnexpectedNetworkMagic,
    /// 尝试分配过大的向量
    OversizedVectorAllocation,
    /// 校验和无效
    InvalidChecksum,
    /// VarInt 编码不是最小的
    NonMinimalVarInt,
    /// 未知的网络魔术值
    UnknownNetworkMagic,
    /// 解析失败
    ParseFailed,
    /// 不支持的隔离见证标志
    UnsupportedSegwitFlag,
    /// 无法识别的网络命令
    UnrecognizedNetworkCommand,
    /// 无效的库存类型
    UnknownInventoryType,
};

/// Encode an object into a vector
pub inline fn serialize(allocator: std.mem.Allocator, data: anytype) ![]u8 {
    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();
    const writer = list.writer();
    var encode = Encodable(@TypeOf(data)).init(data);
    _ = try encode.consensus_encode(writer);
    return list.toOwnedSlice();
}

/// Encode an object into a hex-encoded string
pub inline fn serializeHex(allocator: std.mem.Allocator, data: anytype) ![]u8 {
    const bytes = try serialize(allocator, data);
    defer allocator.free(bytes);
    return hex(allocator, bytes);
}

/// Deserialize an object from a byte slice
pub fn deserialize(comptime T: type, data: []const u8) !T {
    var stream = io.fixedBufferStream(data);
    const reader = stream.reader();
    const result = try Decodable(T).consensus_decode(reader);
    // Ensure all data was consumed
    if (stream.pos != data.len) {
        return Error.ParseFailed;
    }
    return result.value;
}

/// Deserialize an object from a byte slice, but don't require consuming the entire slice
pub fn deserializePartial(comptime T: type, data: []const u8) !struct { value: T, consumed: usize } {
    var stream = io.fixedBufferStream(data);
    const reader = stream.reader();
    const result = try Decodable(T).consensus_decode(reader);
    return .{ .value = result.value, .consumed = result.bytes_read };
}

/// Maximum size, in bytes, of a vector we are allowed to decode
pub const MAX_VEC_SIZE: usize = 4_000_000;

/// Data which can be encoded in a consensus-consistent way
pub fn Encodable(comptime T: type) type {
    return struct {
        value: T,

        pub fn init(value: T) @This() {
            return .{ .value = value };
        }

        pub fn consensus_encode(self: @This(), writer: anytype) !usize {
            return switch (T) {
                bool => {
                    const n: u8 = if (self.value) 1 else 0;
                    try writer.writeByte(n);
                    return 1;
                },
                u8 => {
                    try writer.writeByte(self.value);
                    return 1;
                },
                i8 => {
                    try writer.writeByte(@intCast(self.value));
                    return 1;
                },
                u16 => {
                    try writer.writeInt(u16, self.value, .little);
                    return 2;
                },
                i16 => {
                    try writer.writeInt(i16, self.value, .little);
                    return 2;
                },
                u32 => {
                    try writer.writeInt(u32, self.value, .little);
                    return 4;
                },
                i32 => {
                    try writer.writeInt(i32, self.value, .little);
                    return 4;
                },
                u64 => {
                    try writer.writeInt(u64, self.value, .little);
                    return 8;
                },
                i64 => {
                    try writer.writeInt(i64, self.value, .little);
                    return 8;
                },
                [2]u8, [4]u8, [8]u8, [12]u8, [16]u8, [32]u8, [33]u8 => {
                    try writer.writeAll(self.value[0..]);
                    return self.value.len;
                },
                []const u8 => {
                    const varInt = VarInt.init(@as(u64, @intCast(self.value.len)));
                    var len = try Encodable(VarInt).init(varInt).consensus_encode(writer);
                    for (self.value.items) |c| {
                        try writer.writeByte(c);
                        len += 1;
                    }
                    return len;
                },
                VarInt => {
                    return self.value.consensus_encode(writer);
                },
                CheckedData => {
                    const dataLen = @as(u32, @intCast(T.data.len));
                    try writer.writeInt(u32, dataLen, .little);
                    const checkSum = sha2CheckSum(T.data);
                    try writer.writeAll(checkSum);
                    try writer.writeAll(T.data);
                    return T.data.len + 8;
                },
                else => @compileError("Unsupported type: " ++ @typeName(T)),
            };
        }

        pub fn consensus_encode_with_allocator(self: @This()) !usize {
            _ = self; // autofix
        }
    };
}

pub fn Decodable(comptime T: type) type {
    return struct {
        pub fn consensus_decode(reader: anytype) !struct { value: T, bytes_read: usize } {
            return switch (T) {
                bool => {
                    const n = try reader.readByte();
                    return .{ .value = n != 0, .bytes_read = 1 };
                },
                u8 => {
                    const n = try reader.readByte();
                    return .{ .value = n, .bytes_read = 1 };
                },
                i8 => {
                    const n = try reader.readByte();
                    return .{ .value = @intCast(n), .bytes_read = 1 };
                },
                u16 => {
                    const n = try reader.readInt(u16, .little);
                    return .{ .value = n, .bytes_read = 2 };
                },
                i16 => {
                    const n = try reader.readInt(i16, .little);
                    return .{ .value = n, .bytes_read = 2 };
                },
                u32 => {
                    const n = try reader.readInt(u32, .little);
                    return .{ .value = n, .bytes_read = 4 };
                },
                i32 => {
                    const n = try reader.readInt(i32, .little);
                    return .{ .value = n, .bytes_read = 4 };
                },
                u64 => {
                    const n = try reader.readInt(u64, .little);
                    return .{ .value = n, .bytes_read = 8 };
                },
                i64 => {
                    const n = try reader.readInt(i64, .little);
                    return .{ .value = n, .bytes_read = 8 };
                },
                VarInt => {
                    const result = try VarInt.consensus_decode(reader);
                    return .{ .value = result.value, .bytes_read = result.bytes_read };
                },
                CheckedData => {
                    @compileError("CheckedData is not supported, use consensus_decode_with_allocator instead");
                },
                else => @compileError("Unsupported type: " ++ @typeName(T)),
            };
        }

        /// 使用指定的allocator解码T
        pub fn consensus_decode_with_allocator(allocator: std.mem.Allocator, reader: anytype) !struct { value: T, bytes_read: usize } {
            switch (T) {
                [2]u8, [4]u8, [8]u8, [12]u8, [16]u8, [32]u8, [33]u8 => {
                    const buffer = try allocator.alloc(u8, T.len);
                    const n = try reader.readAll(buffer);
                    return .{ .value = buffer, .bytes_read = n };
                },
                CheckedData => {
                    var dataLen: u32 = try reader.readInt(u32, .little);
                    if (dataLen > MAX_VEC_SIZE) {
                        std.log.err("CheckedData: dataLen > {d}", .{MAX_VEC_SIZE});
                        return Error.OversizedVectorAllocation;
                    }
                    const checkSum: [4]u8 = undefined;
                    const checkSumLen = try reader.read(checkSum);
                    if (checkSumLen != 4) {
                        return Error.InvalidChecksum;
                    }
                    const data = try allocator.?.alloc(u8, dataLen);
                    dataLen = try reader.read(data);
                    std.testing.expect(dataLen == data.len);
                    return .{ .value = CheckedData{ .data = data, .allocator = allocator.? }, .bytes_read = dataLen + 8 };
                },
                else => return Decodable(T).consensus_decode(reader),
            }
        }
    };
}

fn sha2CheckSum(data: []const u8) [4]u8 {
    var sha256d = Sha256D.init(.{});
    sha256d.update(data);
    var checksum: [32]u8 = undefined;
    sha256d.finish(&checksum);
    return [4]u8{ checksum[0], checksum[1], checksum[2], checksum[3] };
}

/// 可变长度无符号整数
pub const VarInt = struct {
    value: u64,

    pub fn init(value: u64) VarInt {
        return .{ .value = value };
    }

    /// 获取编码后的VarInt长度
    /// 返回值：0...0xFC为1，0xFD...(2^16-1)为3，0x10000...(2^32-1)为5，
    /// 其他情况为9
    pub fn len(self: VarInt) usize {
        return switch (self.value) {
            0...0xFC => 1,
            0xFD...0xFFFF => 3,
            0x10000...0xFFFFFFFF => 5,
            else => 9,
        };
    }

    pub fn encode(self: VarInt, writer: anytype) !usize {
        return switch (self.value) {
            0...0xFC => {
                try writer.writeByte(@intCast(self.value));
                return 1;
            },
            0xFD...0xFFFF => {
                try writer.writeByte(0xFD);
                try writer.writeIntLittle(@intCast(self.value));
                return 3;
            },
            0x10000...0xFFFFFFFF => {
                try writer.writeByte(0xFE);
                try writer.writeIntLittle(@intCast(self.value));
                return 5;
            },
            else => {
                try writer.writeByte(0xFF);
                try writer.writeIntLittle(self.value);
                return 9;
            },
        };
    }

    pub fn decode(reader: anytype) !VarInt {
        const n = try reader.readByte();
        return switch (n) {
            0xFF => {
                const x = try reader.readIntLittle(u64);
                if (x < 0x100000000) {
                    return Error.NonMinimalVarInt;
                }
                return VarInt.init(x);
            },
            0xFE => {
                const x = try reader.readIntLittle(u32);
                if (x < 0x10000) {
                    return Error.NonMinimalVarInt;
                }
                return VarInt.init(x);
            },
            0xFD => {
                const x = try reader.readIntLittle(u16);
                if (x < 0xFD) {
                    return Error.NonMinimalVarInt;
                }
                return VarInt.init(x);
            },
            else => return VarInt.init(n),
        };
    }

    /// 编码VarInt, consensus_encode(writer)
    pub fn consensus_encode(self: VarInt, writer: anytype) !usize {
        switch (self.value) {
            0...0xFC => {
                const n = @as(u8, @intCast(self.value));
                return Encodable(u8).init(n).consensus_encode(writer);
            },
            0xFD...0xFFFF => {
                try writer.writeByte(0xFD);
                return Encodable(u16).init(@intCast(self.value)).consensus_encode(writer);
            },
            0x10000...0xFFFFFFFF => {
                try writer.writeByte(0xFE);
                return try Encodable(u32).init(@intCast(self.value)).consensus_encode(writer);
            },
            else => {
                try writer.writeByte(0xFF);
                return Encodable(u64).init(self.value).consensus_encode(writer);
            },
        }
    }

    /// 解码VarInt, consensus_decode(reader)
    pub fn consensus_decode(reader: anytype) !struct { value: VarInt, bytes_read: usize } {
        const n = try reader.readByte();
        switch (n) {
            0xFF => {
                const x = try reader.readInt(u64, .little);
                if (x < 0x100000000) {
                    return Error.NonMinimalVarInt;
                }
                return .{ .value = VarInt{ .value = x }, .bytes_read = 9 };
            },
            0xFE => {
                const x = try reader.readInt(u32, .little);
                if (x < 0x10000) {
                    return Error.NonMinimalVarInt;
                }
                return .{ .value = VarInt{ .value = x }, .bytes_read = 5 };
            },
            0xFD => {
                const x = try reader.readInt(u16, .little);
                if (x < 0xFD) {
                    return Error.NonMinimalVarInt;
                }
                return .{ .value = VarInt{ .value = x }, .bytes_read = 3 };
            },
            else => return .{ .value = VarInt{ .value = n }, .bytes_read = 1 },
        }
    }
};

pub const CheckedData = struct {
    data: []const u8,
    allocator: std.mem.Allocator,

    // 编码CheckedData
    // 4字节数据长度 + 4字节校验和 + 数据
    pub fn consensus_encode(self: *const CheckedData, writer: anytype) !usize {
        try Encodable(u32).init(@as(u32, @intCast(self.data.len))).consensus_encode(writer);
        const checkSum = sha2CheckSum(self.data);
        try Encodable([4]u8).init(checkSum).consensus_encode(writer);
        try writer.writeAll(self.data);
        return 8 + self.data.len;
    }

    /// 使用指定的allocator解码CheckedData
    /// 返回值：CheckedData
    pub fn consensus_decode_with_allocator(allocator: std.mem.Allocator, reader: anytype) !CheckedData {
        var dataLen = try Decodable(u32).consensus_decode(reader);
        if (dataLen.value > MAX_VEC_SIZE) {
            return Error.OversizedVectorAllocation;
        }

        const checkSumLen = try Decodable([4]u8).consensus_decode_with_allocator(allocator, reader);
        defer allocator.free(checkSumLen.value);
        std.testing.expect(checkSumLen.bytes_read == 4);

        const data = try allocator.alloc(u8, dataLen.value);
        dataLen = try reader.read(data);
        std.testing.expect(dataLen == data.len);

        const checkSum = sha2CheckSum(data);
        std.testing.expect(mem.eql(u8, checkSum, checkSumLen.value));
        return .{ .data = data, .allocator = allocator };
    }
};

/// 编码数据并返回长度
pub fn consensusEncodeWithSize(data: []const u8, writer: anytype) !usize {
    const vi_len = VarInt.init(@as(u64, @intCast(data.len))).len();
    try writer.writeInt(u32, data.len, .little);
    try writer.writeAll(data);
    return vi_len + data.len;
}

fn testVarIntEncode(n: u8, x: []const u8) !VarInt {
    var input = [_]u8{0} ** 9;
    input[0] = n;
    @memcpy(input[1..], x);
    const value = try deserializePartial(VarInt, &input);
    return value.value;
}

//   fn test_varint_len(varint: VarInt, expected: usize) {
//         let mut encoder = io::Cursor::new(vec![]);
//         assert_eq!(varint.consensus_encode(&mut encoder).unwrap(), expected);
//         assert_eq!(varint.len(), expected);
//     }

fn testVarIntLen(varint: VarInt, expected: usize) void {
    const buffer = std.testing.allocator.alloc(u8, expected) catch unreachable;
    defer std.testing.allocator.free(buffer);
    const encoder = io.fixedBufferStream(buffer).writer();
    const len = varint.consensus_encode(encoder) catch unreachable;
    std.testing.expect(len == expected);
}

fn u64ToArrayLe(n: u64) [8]u8 {
    var buffer = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 };
    var fbs = std.io.fixedBufferStream(&buffer);
    fbs.writer().writeInt(u64, n, .little) catch unreachable;
    return buffer;
}

test "serialize_int_test" {
    // bool
    {
        const args = [_]bool{ false, true };
        const expected = [_][]const u8{
            &[_]u8{0},
            &[_]u8{1},
        };
        for (args, expected) |arg, exp| {
            const allocator = testing.allocator;
            const encoded = try serialize(allocator, arg);
            defer allocator.free(encoded);
            try testing.expect(std.mem.eql(u8, encoded, exp));
        }
    }

    // u8
    {
        const args = [_]u8{ 1, 0, 255 };
        const expected = [_][]const u8{
            &[_]u8{1},
            &[_]u8{0},
            &[_]u8{255},
        };
        for (args, expected) |arg, exp| {
            const allocator = testing.allocator;
            const encoded = try serialize(allocator, arg);
            defer allocator.free(encoded);
            try testing.expect(std.mem.eql(u8, encoded, exp));
        }
    }

    // u16
    {
        const args = [_]u16{ 1, 256, 5000 };
        const expected = [_][]const u8{
            &[_]u8{ 1, 0 },
            &[_]u8{ 0, 1 },
            &[_]u8{ 136, 19 },
        };
        for (args, expected) |arg, exp| {
            const encoded = try serialize(testing.allocator, arg);
            defer testing.allocator.free(encoded);
            try testing.expect(std.mem.eql(u8, encoded, exp));
        }
    }

    // u32
    {
        const args = [_]u32{ 1, 256, 5000, 500000, 168430090 };
        const expected = [_][]const u8{
            &[_]u8{ 1, 0, 0, 0 },
            &[_]u8{ 0, 1, 0, 0 },
            &[_]u8{ 136, 19, 0, 0 },
            &[_]u8{ 32, 161, 7, 0 },
            &[_]u8{ 10, 10, 10, 10 },
        };
        for (args, expected) |arg, exp| {
            const encoded = try serialize(testing.allocator, arg);
            defer testing.allocator.free(encoded);
            try testing.expect(std.mem.eql(u8, encoded, exp));
        }
    }

    // i32
    {
        const args = [_]i32{ -1, -256, -5000, -500000, -168430090, 1, 256, 5000, 500000, 168430090 };
        const expected = [_][]const u8{
            &[_]u8{ 255, 255, 255, 255 },
            &[_]u8{ 0, 255, 255, 255 },
            &[_]u8{ 120, 236, 255, 255 },
            &[_]u8{ 224, 94, 248, 255 },
            &[_]u8{ 246, 245, 245, 245 },
            &[_]u8{ 1, 0, 0, 0 },
            &[_]u8{ 0, 1, 0, 0 },
            &[_]u8{ 136, 19, 0, 0 },
            &[_]u8{ 32, 161, 7, 0 },
            &[_]u8{ 10, 10, 10, 10 },
        };
        for (args, expected) |arg, exp| {
            const encoded = try serialize(testing.allocator, arg);
            defer testing.allocator.free(encoded);
            try testing.expect(std.mem.eql(u8, encoded, exp));
        }
    }

    // u64
    {
        const args = [_]u64{ 1, 256, 5000, 500000, 723401728380766730 };
        const expected = [_][]const u8{
            &[_]u8{ 1, 0, 0, 0, 0, 0, 0, 0 },
            &[_]u8{ 0, 1, 0, 0, 0, 0, 0, 0 },
            &[_]u8{ 136, 19, 0, 0, 0, 0, 0, 0 },
            &[_]u8{ 32, 161, 7, 0, 0, 0, 0, 0 },
            &[_]u8{ 10, 10, 10, 10, 10, 10, 10, 10 },
        };
        for (args, expected) |arg, exp| {
            const encoded = try serialize(testing.allocator, arg);
            defer testing.allocator.free(encoded);
            try testing.expect(std.mem.eql(u8, encoded, exp));
        }
    }

    // i64
    {
        const args = [_]i64{ -1, -256, -5000, -500000, -723401728380766730, 1, 256, 5000, 500000, 723401728380766730 };
        const expected = [_][]const u8{
            &[_]u8{ 255, 255, 255, 255, 255, 255, 255, 255 },
            &[_]u8{ 0, 255, 255, 255, 255, 255, 255, 255 },
            &[_]u8{ 120, 236, 255, 255, 255, 255, 255, 255 },
            &[_]u8{ 224, 94, 248, 255, 255, 255, 255, 255 },
            &[_]u8{ 246, 245, 245, 245, 245, 245, 245, 245 },
            &[_]u8{ 1, 0, 0, 0, 0, 0, 0, 0 },
            &[_]u8{ 0, 1, 0, 0, 0, 0, 0, 0 },
            &[_]u8{ 136, 19, 0, 0, 0, 0, 0, 0 },
            &[_]u8{ 32, 161, 7, 0, 0, 0, 0, 0 },
            &[_]u8{ 10, 10, 10, 10, 10, 10, 10, 10 },
        };
        for (args, expected) |arg, exp| {
            const encoded = try serialize(testing.allocator, arg);
            defer testing.allocator.free(encoded);
            try testing.expect(std.mem.eql(u8, encoded, exp));
        }
    }
}

test "serialize_varint_test" {
    {
        const args = [_]VarInt{ VarInt.init(10), VarInt.init(0xFC), VarInt.init(0xFD), VarInt.init(0xFFF), VarInt.init(0xF0F0F0F), VarInt.init(0xF0F0F0F0F0E0) };
        const encoded = [_][]const u8{
            &[_]u8{10},
            &[_]u8{0xFC},
            &[_]u8{ 0xFD, 0xFD, 0 },
            &[_]u8{ 0xFD, 0xFF, 0xF },
            &[_]u8{ 0xFE, 0xF, 0xF, 0xF, 0xF },
            &[_]u8{ 0xFF, 0xE0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0, 0 },
        };
        for (args, encoded) |arg, exp| {
            const got = try serialize(testing.allocator, arg);
            defer testing.allocator.free(got);
            try testing.expect(std.mem.eql(u8, got, exp));
        }
    }
    {
        const preArgs = [_]u8{ 0xFF, 0xFE, 0xFD };
        const args = [_]VarInt{ VarInt.init(0x100000000), VarInt.init(0x10000), VarInt.init(0xFD) };
        const encoded = [_][8]u8{
            u64ToArrayLe(0x100000000),
            u64ToArrayLe(0x10000),
            u64ToArrayLe(0xFD),
        };
        for (0..args.len) |i| {
            const got = try testVarIntEncode(preArgs[i], &encoded[i]);
            try testing.expectEqual(got.value, args[i].value);
        }
    }

    {
        // Test that length calc is working correctly
        // test_varint_len(VarInt(0), 1);
        // test_varint_len(VarInt(0xFC), 1);
        // test_varint_len(VarInt(0xFD), 3);
        // test_varint_len(VarInt(0xFFFF), 3);
        // test_varint_len(VarInt(0x10000), 5);
        // test_varint_len(VarInt(0xFFFFFFFF), 5);
        // test_varint_len(VarInt(0xFFFFFFFF+1), 9);
        // test_varint_len(VarInt(u64::max_value()), 9);

    }
}

test "encodable" {
    var _i8 = Encodable(i8).init(1);
    var buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer buffer.deinit();
    const nsize = try _i8.consensus_encode(buffer.writer());
    try std.testing.expectEqual(nsize, 1);
}

test "serialize and deserialize" {
    const allocator = testing.allocator;

    // Test integers
    {
        const original: u32 = 12345678;
        const encoded = try serialize(allocator, original);
        defer allocator.free(encoded);

        const decoded = try deserialize(u32, encoded);
        try testing.expectEqual(original, decoded);
    }

    // Test VarInt
    {
        const original = VarInt{ .value = 0xFFF };
        const encoded = try serialize(allocator, original);
        defer allocator.free(encoded);

        const decoded = try deserialize(VarInt, encoded);
        try testing.expectEqual(original.value, decoded.value);
    }

    // Test partial deserialization
    {
        const original: u16 = 12345;
        const buffer = try allocator.alloc(u8, 4);
        defer allocator.free(buffer);

        var stream = io.fixedBufferStream(buffer);
        _ = try Encodable(u16).init(original).consensus_encode(stream.writer());
        _ = try Encodable(u8).init(42).consensus_encode(stream.writer());

        const result = try deserializePartial(u16, buffer);
        try testing.expectEqual(original, result.value);
        try testing.expectEqual(@as(usize, 2), result.consumed);
    }
}
