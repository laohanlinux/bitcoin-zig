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

const hash = @import("hash");
const Sha256D = hash.HashEngine(.sha256d);
const hex = hash.hex;
const hashType = @import("hashtypes");
const TxId = hashType.Txid;

pub const Reader = io.FixedBufferStream([]const u8).Reader;
pub const Writer = io.FixedBufferStream([]u8).Writer;

/// encoding error
pub const Error = error{
    /// I/O error
    IoError,
    /// PSBT related error
    PsbtError,
    /// unexpected network magic
    UnexpectedNetworkMagic,
    /// attempt to allocate too large a vector
    OversizedVectorAllocation,
    /// invalid checksum
    InvalidChecksum,
    /// VarInt is not minimally encoded
    NonMinimalVarInt,
    /// unknown network magic
    UnknownNetworkMagic,
    /// data not consumed entirely when explicitly deserializing"
    ParseFailed,
    /// unsupported segwit flag
    UnsupportedSegwitFlag,
    /// unrecognized network command
    UnrecognizedNetworkCommand,
    /// unknown inventory type
    UnknownInventoryType,
};

/// Encode an object into a vector
pub inline fn serialize(allocator: std.mem.Allocator, data: anytype) ![]u8 {
    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();
    const writer = list.writer();
    var encode = Encodable(@TypeOf(data)).init(data);
    _ = try encode.consensusEncode(writer);
    return list.toOwnedSlice();
}

/// Encode an object into a hex-encoded string
pub inline fn serializeHex(allocator: std.mem.Allocator, data: anytype) ![]u8 {
    const bytes = try serialize(allocator, data);
    defer allocator.free(bytes);
    return hex(allocator, bytes);
}

/// Decode a vector of objects from a byte slice, return a slice of the objects
pub fn decodeVec(allocator: std.mem.Allocator, comptime T: type, data: []const u8) ![]T {
    var reader = std.io.fixedBufferStream(data);
    const varint = try VarInt.init(0).consensusDecode(reader.reader());
    const len = varint.value;
    const byteSize = len * @sizeOf(T);
    if (byteSize > MAX_VEC_SIZE) {
        return Error.OversizedVectorAllocation;
    }
    const result = try allocator.alloc(T, len);
    errdefer allocator.free(result);
    var i: usize = 0;
    while (i < len) : (i += 1) {
        result[i] = try Decodable(T).init(.{ .allocator = allocator }).consensusDecode(reader);
    }
    return result;
}

pub fn deserializeWithAllocator(allocator: std.mem.Allocator, comptime T: type, data: []const u8) !T {
    var decoder = Decodable(T).init(.{ .allocator = allocator });
    var reader = std.io.fixedBufferStream(data);
    const result = try decoder.consensusDecode(reader.reader());
    return result.value;
}

/// Deserialize an object from a byte slice
pub fn deserialize(comptime T: type, data: []const u8) !T {
    var decoder = Decodable(T).init(.{});
    const result = try decoder.consensusDecode(data);
    // Ensure all data was consumed
    if (result.bytes_read != data.len) {
        // data not consumed entirely when explicitly deserializing
        return Error.ParseFailed;
    }
    return result.value;
}

fn deserializeWithReader(comptime T: type, reader: std.io.FixedBufferStream([]const u8).Reader) !T {
    var decoder = Decodable(T).init(.{});
    const result = try decoder.consensusDecode(reader);
    return result.value;
}

/// Deserialize an object from a byte slice, but don't require consuming the entire slice
pub fn deserializePartial(comptime T: type, data: []const u8) !struct { value: T, consumed: usize } {
    var decoder = Decodable(T).init(.{});
    var reader = std.io.fixedBufferStream(data);
    const result = try decoder.consensusDecode(reader.reader());
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

        pub fn consensusEncode(self: @This(), writer: anytype) !usize {
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
                    const len = try Encodable(VarInt).init(varInt).consensusEncode(writer);
                    const dataLen = try writer.writeAll(self.value);
                    std.debug.assert(dataLen == self.value.len);
                    return len + dataLen;
                },
                VarInt => {
                    return self.value.consensusEncode(writer);
                },
                CheckedData => {
                    var dataLen = @as(u32, @intCast(self.value.data.len));
                    try writer.writeInt(u32, dataLen, .little);
                    const checkSum = sha2CheckSum(self.value.data);
                    dataLen = try writer.writeAll(&checkSum);
                    std.debug.assert(dataLen == 4);
                    dataLen = try writer.writeAll(self.value.data);
                    std.debug.assert(dataLen == self.value.data.len);
                    return self.value.data.len + 8;
                },
                else => @compileError("Unsupported type: " ++ @typeName(T)),
            };
        }
    };
}

/// Decode an object from a byte slice
pub fn Decodable(comptime T: type) type {
    return struct {
        const Option = struct {
            allocator: ?std.mem.Allocator = null,
        };

        const Decoder = struct {
            value: T = undefined,
            bytes_read: usize = 0,
            allocator: ?std.mem.Allocator = null,
            pub fn consensusDecode(self: *Decoder, reader: Reader) !*Decoder {
                if (std.mem.startsWith(u8, @typeName(T), "encode.Vec")) {
                    const vec = try Vec(T).consensusDecode(self.allocator.?, reader);
                    self.value = vec;
                    self.bytes_read = vec.bytes_read;
                    return self;
                }
                switch (T) {
                    bool => {
                        const n = try reader.readByte();
                        self.value = n != 0;
                        self.bytes_read = 1;
                        return self;
                    },
                    u8 => {
                        const n = try reader.readByte();
                        self.value = n;
                        self.bytes_read = 1;
                        return self;
                    },
                    i8 => {
                        const n = try reader.readByte();
                        self.value = n;
                        self.bytes_read = 1;
                        return self;
                    },
                    u16 => {
                        const n = reader.readInt(u16, .little) catch {
                            return error.ParseFailed;
                        };
                        self.value = n;
                        self.bytes_read = 2;
                        return self;
                    },
                    i16 => {
                        const n = try reader.readInt(i16, .little);
                        self.value = n;
                        self.bytes_read = 2;
                        return self;
                    },
                    u32 => {
                        const n = reader.readInt(u32, .little) catch {
                            return error.ParseFailed;
                        };
                        self.value = n;
                        self.bytes_read = 4;
                        return self;
                    },
                    i32 => {
                        const n = reader.readInt(i32, .little) catch {
                            return error.ParseFailed;
                        };
                        self.value = n;
                        self.bytes_read = 4;
                        return self;
                    },
                    u64 => {
                        const n = reader.readInt(u64, .little) catch {
                            return error.ParseFailed;
                        };
                        self.value = n;
                        self.bytes_read = 8;
                        return self;
                    },
                    i64 => {
                        const n = reader.readInt(i64, .little) catch {
                            return error.ParseFailed;
                        };
                        self.value = n;
                        self.bytes_read = 8;
                        return self;
                    },
                    VarInt => {
                        const result = try VarInt.consensusDecode(reader);
                        self.value = result.value;
                        self.bytes_read = result.bytes_read;
                        return self;
                    },
                    [2]u8, [4]u8, [8]u8, [12]u8, [16]u8, [32]u8, [33]u8 => {
                        // |len(VarInt) | data(slice) |
                        const varInt = try VarInt.consensusDecode(reader);
                        if (varInt.value.value > MAX_VEC_SIZE) {
                            return Error.OversizedVectorAllocation;
                        }
                        // the length of the data must be >= 1
                        std.debug.assert(varInt.value.value >= 1);

                        // if ((data.len - 1) != varInt.value.value) {
                        //     return Error.ParseFailed;
                        // }
                        const n = reader.readAll(self.value) catch {
                            return Error.ParseFailed;
                        };
                        if (n != self.value.len) {
                            return Error.ParseFailed;
                        }
                        self.bytes_read = n;
                        return self;
                    },
                    []u8, []const u8 => {
                        // |len(VarInt) | data(slice) |
                        const varInt = try VarInt.consensusDecode(reader);
                        if (varInt.value.value > MAX_VEC_SIZE) {
                            return Error.OversizedVectorAllocation;
                        }
                        // the length of the data must be >= 1
                        std.debug.assert(varInt.value.value >= 1);

                        // if ((data.len - 1) != varInt.value.value) {
                        //     return Error.ParseFailed;
                        // }
                        const data_ = self.allocator.?.alloc(u8, varInt.value.value) catch {
                            return Error.ParseFailed;
                        };
                        errdefer self.allocator.?.free(data_);
                        const n = reader.readAll(data_) catch {
                            return Error.ParseFailed;
                        };
                        self.value = data_;
                        self.bytes_read = n;
                        return self;
                    },
                    CheckedData => {
                        // |len(u32) | checksum(4) | data(slice) |
                        var dataLen: u32 = try reader.readInt(u32, .little);
                        if (dataLen > MAX_VEC_SIZE) {
                            return Error.OversizedVectorAllocation;
                        }
                        const checkSum: [4]u8 = undefined;
                        const checkSumLen = try reader.read(checkSum);
                        if (checkSumLen != 4) {
                            return Error.InvalidChecksum;
                        }
                        const data_ = try self.allocator.alloc(u8, dataLen);
                        dataLen = try reader.read(data_);
                        self.value = CheckedData{ .data = data_, .allocator = self.allocator };
                        self.bytes_read = dataLen + 8;
                        return self;
                    },
                    Vec(T) => {
                        const vec = try Vec(T).consensusDecode(self.allocator, reader);
                        self.value = vec;
                        self.bytes_read = vec.bytes_read;
                        return self;
                    },
                    else => @compileError("Unsupported type: " ++ @typeName(T)),
                }
            }

            pub fn deinit(self: Decoder) void {
                switch (T) {
                    [2]u8, [4]u8, [8]u8, [12]u8, [16]u8, [32]u8, [33]u8, []u8, []const u8 => {
                        std.debug.assert(self.allocator != null);
                        self.allocator.?.free(self.value);
                    },
                    CheckedData => {
                        self.value.allocator.free(self.value.data);
                    },
                    else => {},
                }
            }
        };

        // init Decoder with value and option
        pub fn init(option: Option) Decoder {
            return .{ .bytes_read = 0, .allocator = option.allocator };
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

/// VarInt is a variable-length unsigned integer.
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
    pub fn consensusEncode(self: VarInt, writer: anytype) !usize {
        switch (self.value) {
            0...0xFC => {
                const n = @as(u8, @intCast(self.value));
                // 1 byte
                const dataLen = try Encodable(u8).init(n).consensusEncode(writer);
                std.debug.assert(dataLen == 1);
                return dataLen;
            },
            0xFD...0xFFFF => {
                try writer.writeByte(0xFD);
                const dataLen = try Encodable(u16).init(@intCast(self.value)).consensusEncode(writer);
                std.debug.assert(dataLen == 2);
                // 1 byte + 2 bytes
                return dataLen + 1;
            },
            0x10000...0xFFFFFFFF => {
                try writer.writeByte(0xFE);
                const dataLen = try Encodable(u32).init(@intCast(self.value)).consensusEncode(writer);
                std.debug.assert(dataLen == 4);
                // 1 byte + 4 bytes
                return dataLen + 1;
            },
            else => {
                try writer.writeByte(0xFF);
                const dataLen = try Encodable(u64).init(self.value).consensusEncode(writer);
                std.debug.assert(dataLen == 8);
                // 1 byte + 8 bytes
                return dataLen + 1;
            },
        }
    }

    /// 解码VarInt, consensus_decode(reader)
    pub fn consensusDecode(reader: Reader) !struct { value: VarInt, bytes_read: usize } {
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

pub fn Vec(comptime T: type) type {
    return struct {
        data: std.ArrayList(T),

        pub fn init(data: std.ArrayList(T)) Vec(T) {
            return .{ .data = data };
        }

        // /// Encode a vector of objects
        // pub fn consensusEncode(self: *const Vec(T), writer: anytype) !usize {
        //     return self.consensus_encode(writer);
        // }

        /// Decode a vector of objects
        pub fn consensusDecode(allocator: std.mem.Allocator, reader: Reader) !Vec(T) {
            const varint = try VarInt.consensusDecode(reader);
            const len = varint.value;
            const byteSize = len.value * @sizeOf(T);
            if (byteSize > MAX_VEC_SIZE) {
                return Error.OversizedVectorAllocation;
            }
            const result = try allocator.alloc(T, len.value);
            errdefer allocator.free(result);
            var i: usize = 0;
            while (i < len.value) : (i += 1) {
                var dec = Decodable(T).init(.{ .allocator = allocator });
                const dec_result = try dec.consensusDecode(reader);
                result[i] = dec_result.value;
            }
            return result;
        }

        pub fn deinit(self: *Vec(T)) void {
            self.data.deinit();
        }

        pub fn toOwned(self: Vec(T)) []T {
            return self.data.toOwnedSlice();
        }
    };
}

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
    @memcpy(input[1..(1 + x.len)], x);
    const value = try deserializePartial(VarInt, &input);
    return value.value;
}

fn testVarIntLen(varint: VarInt, expected: usize) !void {
    var buffer = std.ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();
    const writer = buffer.writer();
    const len = try varint.consensusEncode(writer);
    try std.testing.expectEqual(expected, len);
}

fn toArrayLe(value: anytype, comptime size: usize) [size]u8 {
    var buffer = [_]u8{0} ** size;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();
    switch (@TypeOf(value)) {
        u8, i8 => writer.writeInt(u8, @intCast(value), .little) catch unreachable,
        u16, i16 => writer.writeInt(u16, @intCast(value), .little) catch unreachable,
        u32, i32 => writer.writeInt(u32, @intCast(value), .little) catch unreachable,
        u64, i64 => writer.writeInt(u64, @intCast(value), .little) catch unreachable,
        comptime_int => {
            if (value >= 0 and value <= std.math.maxInt(u8)) {
                writer.writeInt(u8, @intCast(value), .little) catch unreachable;
            } else if (value >= std.math.minInt(i8) and value < 0) {
                writer.writeInt(i8, @intCast(value), .little) catch unreachable;
            } else if (value >= 0 and value <= std.math.maxInt(u16)) {
                writer.writeInt(u16, @intCast(value), .little) catch unreachable;
            } else if (value >= std.math.minInt(i16) and value < 0) {
                writer.writeInt(i16, @intCast(value), .little) catch unreachable;
            } else if (value >= 0 and value <= std.math.maxInt(u32)) {
                writer.writeInt(u32, @intCast(value), .little) catch unreachable;
            } else if (value >= std.math.minInt(i32) and value < 0) {
                writer.writeInt(i32, @intCast(value), .little) catch unreachable;
            } else if (value >= 0) {
                writer.writeInt(u64, @intCast(value), .little) catch unreachable;
            } else {
                writer.writeInt(i64, @intCast(value), .little) catch unreachable;
            }
        },
        else => @compileError("Unsupported type for toArrayLe: " ++ @typeName(@TypeOf(value))),
    }
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
            toArrayLe(0x100000000, 8),
            toArrayLe(0x10000, 8),
            toArrayLe(0xFD, 8),
        };
        for (0..args.len) |i| {
            const got = try testVarIntEncode(preArgs[i], &encoded[i]);
            try testing.expectEqual(got.value, args[i].value);
        }
    }

    // Test that length calc is working correctly
    {
        try testVarIntLen(VarInt.init(0), 1);
        try testVarIntLen(VarInt.init(0xFC), 1);
        try testVarIntLen(VarInt.init(0xFD), 3);
        try testVarIntLen(VarInt.init(0xFFFF), 3);
        try testVarIntLen(VarInt.init(0x10000), 5);
        try testVarIntLen(VarInt.init(0xFFFFFFFF), 5);
        try testVarIntLen(VarInt.init(0xFFFFFFFF + 1), 9);
        try testVarIntLen(VarInt.init(std.math.maxInt(u64)), 9);
    }
}

test "deserialize_nonminimal_vec" {
    // Check the edges for variant int
    _ = testVarIntEncode(0xFF, &toArrayLe(0x100000000 - 1, 8)) catch |err| {
        try testing.expect(err == error.NonMinimalVarInt);
    };
    _ = testVarIntEncode(0xFE, &toArrayLe(0x10000 - 1, 4)) catch |err| {
        try testing.expect(err == error.NonMinimalVarInt);
    };
    _ = testVarIntEncode(0xFD, &toArrayLe(0xFD - 1, 2)) catch |err| {
        try testing.expect(err == error.NonMinimalVarInt);
    };
    std.testing.log_level = .debug;

    {
        _ = deserializeWithAllocator(testing.allocator, []u8, &[_]u8{ 0xfd, 0x00, 0x00 }) catch |err| {
            try testing.expect(err == error.NonMinimalVarInt);
        };

        _ = deserializeWithAllocator(testing.allocator, []u8, &[_]u8{ 0xfd, 0xfc, 0x00 }) catch |err| {
            try testing.expect(err == error.NonMinimalVarInt);
        };

        _ = deserializeWithAllocator(testing.allocator, []u8, &[_]u8{ 0xfe, 0xff, 0x00, 0x00, 0x00 }) catch |err| {
            try testing.expect(err == error.NonMinimalVarInt);
        };
        _ = deserializeWithAllocator(testing.allocator, []u8, &[_]u8{ 0xfe, 0xff, 0xff, 0x00, 0x00 }) catch |err| {
            try testing.expect(err == error.NonMinimalVarInt);
        };
        _ = deserializeWithAllocator(testing.allocator, []u8, &[_]u8{ 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }) catch |err| {
            try testing.expect(err == error.NonMinimalVarInt);
        };
        _ = deserializeWithAllocator(testing.allocator, []u8, &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }) catch |err| {
            try testing.expect(err == error.NonMinimalVarInt);
        };
    }

    var vec256 = [_]u8{0x00} ** 259;
    vec256[0] = 0xfd;
    vec256[1] = 0x00;
    vec256[2] = 0x01;
    const result = deserializeWithAllocator(testing.allocator, []u8, &vec256) catch unreachable;
    defer testing.allocator.free(result);
    var vec253 = [_]u8{0x00} ** 256;
    vec253[0] = 0xfd;
    vec253[1] = 0xfd;
    vec253[2] = 0x00;
    const result2 = deserializeWithAllocator(testing.allocator, []u8, &vec253) catch unreachable;
    defer testing.allocator.free(result2);
}

// test "serialize_strbuf_test" {
//     const str: []const u8 = "Andrew";
//     const encoded = try serialize(testing.allocator, str);
//     defer testing.allocator.free(encoded);
//     try testing.expect(std.mem.eql(u8, encoded, &[_]u8{ 6, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77 }));
// }

// test "deserialize_int_test" {
//     // bool
//     {
//         _ = deserialize(bool, &[_]u8{ 58, 0 }) catch |err| {
//             try testing.expect(err == error.ParseFailed);
//         };
//         _ = deserialize(bool, &[_]u8{58}) catch unreachable;
//         _ = deserialize(bool, &[_]u8{1}) catch unreachable;
//         _ = deserialize(bool, &[_]u8{0}) catch unreachable;
//         _ = deserialize(bool, &[_]u8{ 0, 1 }) catch |err| {
//             try testing.expect(err == error.ParseFailed);
//         };
//     }

//     // u8
//     {
//         _ = deserialize(u8, &[_]u8{58}) catch unreachable;
//     }

//     // u16
//     {
//         const got = try deserialize(u16, &[_]u8{ 0x01, 0x02 });
//         try testing.expectEqual(got, 0x0201);
//         const got2 = try deserialize(u16, &[_]u8{ 0xAB, 0xCD });
//         try testing.expectEqual(got2, 0xCDAB);
//         const got3 = try deserialize(u16, &[_]u8{ 0xA0, 0x0D });
//         try testing.expectEqual(got3, 0xDA0);
//         _ = deserialize(u16, &[_]u8{1}) catch |err| {
//             try testing.expect(err == error.ParseFailed);
//         };
//     }
//     // u32
//     {
//         const got = try deserialize(u32, &[_]u8{ 0xAB, 0xCD, 0, 0 });
//         try testing.expectEqual(got, 0xCDAB);
//         const got2 = try deserialize(u32, &[_]u8{ 0xA0, 0x0D, 0xAB, 0xCD });
//         try testing.expectEqual(got2, 0xCDAB0DA0);
//         _ = deserialize(u32, &[_]u8{ 1, 2, 3 }) catch |err| {
//             try testing.expect(err == error.ParseFailed);
//         };

//         const got3 = try deserialize(i32, &[_]u8{ 0xAB, 0xCD, 0, 0 });
//         try testing.expectEqual(got3, 0xCDAB);
//         const got4 = try deserialize(i32, &[_]u8{ 0xA0, 0x0D, 0xAB, 0x2D });
//         try testing.expectEqual(got4, 0x2DAB0DA0);
//         _ = deserialize(i32, &[_]u8{ 1, 2, 3 }) catch |err| {
//             try testing.expect(err == error.ParseFailed);
//         };
//     }

//     // u64
//     {
//         const got = try deserialize(u64, &[_]u8{ 0xAB, 0xCD, 0, 0, 0, 0, 0, 0 });
//         try testing.expectEqual(got, 0xCDAB);
//         const got2 = try deserialize(u64, &[_]u8{ 0xA0, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99 });
//         try testing.expectEqual(got2, 0x99000099CDAB0DA0);
//         _ = deserialize(u64, &[_]u8{ 1, 2, 3, 4, 5, 6, 7 }) catch |err| {
//             try testing.expect(err == error.ParseFailed);
//         };

//         const got3 = try deserialize(i64, &[_]u8{ 0xAB, 0xCD, 0, 0, 0, 0, 0, 0 });
//         try testing.expectEqual(got3, 0xCDAB);
//         const got4 = try deserialize(i64, &[_]u8{ 0xA0, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99 });
//         try testing.expectEqual(got4, -0x66ffff663254f260);
//         _ = deserialize(i64, &[_]u8{ 1, 2, 3, 4, 5, 6, 7 }) catch |err| {
//             try testing.expect(err == error.ParseFailed);
//         };
//     }
// }

test "deserialize_vec_test" {
    const got = try deserializeWithAllocator(testing.allocator, []const u8, &[_]u8{ 3, 2, 3, 4 });
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, got, &[_]u8{ 2, 3, 4 });
    _ = deserializeWithAllocator(testing.allocator, []const u8, &[_]u8{ 4, 2, 3, 4, 5, 6 }) catch |err| {
        testing.expect(err == error.ParseFailed) catch unreachable;
    };

    _ = deserializeWithAllocator(testing.allocator, Vec(u64), &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0xa, 0xa, 0x3a }) catch |err| {
        testing.expect(err == error.OversizedVectorAllocation) catch unreachable;
    };
}

// test "serialize_checked_data" {
//     const data = CheckedData{ .data = &[_]u8{ 1, 2, 3, 4, 5 }, .allocator = testing.allocator };
//     const encoded = try serialize(testing.allocator, data);
//     defer testing.allocator.free(encoded);
//     try testing.expect(std.mem.eql(u8, encoded, &[_]u8{ 5, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5 }));
//     std.testing.log_level = .debug;
// }

// test "encodable" {
//     var _i8 = Encodable(i8).init(1);
//     var buffer = std.ArrayList(u8).init(std.testing.allocator);
//     defer buffer.deinit();
//     const nsize = try _i8.consensus_encode(buffer.writer());
//     try std.testing.expectEqual(nsize, 1);
// }

// test "serialize and deserialize" {
//     const allocator = testing.allocator;

//     // Test integers
//     {
//         const original: u32 = 12345678;
//         const encoded = try serialize(allocator, original);
//         defer allocator.free(encoded);

//         const decoded = try deserialize(u32, encoded);
//         try testing.expectEqual(original, decoded);
//     }

//     // Test VarInt
//     {
//         const original = VarInt{ .value = 0xFFF };
//         const encoded = try serialize(allocator, original);
//         defer allocator.free(encoded);

//         const decoded = try deserialize(VarInt, encoded);
//         try testing.expectEqual(original.value, decoded.value);
//     }

//     // Test partial deserialization
//     {
//         const original: u16 = 12345;
//         const buffer = try allocator.alloc(u8, 4);
//         defer allocator.free(buffer);

//         var stream = io.fixedBufferStream(buffer);
//         _ = try Encodable(u16).init(original).consensus_encode(stream.writer());
//         _ = try Encodable(u8).init(42).consensus_encode(stream.writer());

//         const result = try deserializePartial(u16, buffer);
//         try testing.expectEqual(original, result.value);
//         try testing.expectEqual(@as(usize, 2), result.consumed);
//     }
// }

test "serialize_vec_test" {
    // const vec = Vec(u8).init(testing.allocator);
    std.testing.log_level = .debug;
    std.log.info("vec: {s}\n", .{@typeName(Vec(u8))});
}
