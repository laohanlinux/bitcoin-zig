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
const hex = hash.hex;
const hashType = @import("hashtypes");
const TxId = hashType.Txid;

pub const Reader = io.FixedBufferStream([]const u8).Reader;
pub const Writer = io.FixedBufferStream([]const u8).Writer;

const Sha256D = hashType.Hash256D;

/// EncoderOption is the option for the encoder
pub const EncoderOption = struct {
    allocator: ?std.mem.Allocator = null,
};
/// DecoderOption is the option for the decoder
pub const DecoderOption = struct {
    allocator: ?std.mem.Allocator = null,
};

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
pub fn deserializedVec(allocator: std.mem.Allocator, comptime T: type, data: []const u8) ![]T {
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader();
    const varint = try VarInt.consensusDecode(.{}, reader);
    const len = varint.value;
    const byteSize = len * @sizeOf(T);
    if (byteSize > MAX_VEC_SIZE) {
        return Error.OversizedVectorAllocation;
    }
    const result = try allocator.alloc(T, len);
    errdefer allocator.free(result);
    var i: usize = 0;
    while (i < len) : (i += 1) {
        result[i] = try Decodable(T).consensusDecode(.{ .allocator = allocator }, reader);
    }
    return result;
}

pub fn deserializeWithAllocator(allocator: std.mem.Allocator, comptime T: type, data: []const u8) !T {
    const result = try deserializePartialWithAllocator(allocator, T, data);
    if (result.consumed != data.len) {
        if (hasFn(T, "deinit")) {
            std.debug.print("it has deinit function, {s}\n", .{@typeName(T)});
        }
        std.debug.print("the consumed is not equal to the data len, {s}\n", .{@typeName(T)});
        return Error.ParseFailed;
    }
    return result.value;
}

/// Deserialize an object from a byte slice
pub fn deserialize(comptime T: type, data: []const u8) !T {
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader();
    const result = try Decodable(T).consensusDecode(.{}, reader);
    // Ensure all data was consumed
    if (stream.pos != data.len) {
        // data not consumed entirely when explicitly deserializing
        return Error.ParseFailed;
    }
    return result;
}

fn deserializeWithReader(comptime T: type, reader: std.io.FixedBufferStream([]const u8).Reader) !T {
    var decoder = Decodable(T).init(.{});
    const result = try decoder.consensusDecode(reader);
    return result.value;
}

/// Deserialize an object from a byte slice, but don't require consuming the entire slice
pub fn deserializePartial(comptime T: type, data: []const u8) !struct { value: T, consumed: usize } {
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader();
    const result = try Decodable(T).consensusDecode(.{ .allocator = null }, reader);
    return .{ .value = result, .consumed = reader.context.pos };
}

/// Deserialize an object from a byte slice, but don't require consuming the entire slice
pub fn deserializePartialWithAllocator(allocator: std.mem.Allocator, comptime T: type, data: []const u8) !struct { value: T, consumed: usize } {
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader();
    const result = try Decodable(T).consensusDecode(DecoderOption{ .allocator = allocator }, reader);
    return .{ .value = result, .consumed = reader.context.pos };
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

        pub fn consensusEncode(self: @This(), writer: anytype) Error!usize {
            return switch (T) {
                bool => {
                    const n: u8 = if (self.value) 1 else 0;
                    writer.writeByte(n) catch unreachable;
                    return 1;
                },
                u8, i8 => {
                    const n = @as(u8, @intCast(self.value));
                    writer.writeByte(n) catch {
                        return Error.ParseFailed;
                    };
                    return 1;
                },
                u16, i16, u32, i32, u64, i64 => {
                    writer.writeInt(T, self.value, .little) catch unreachable;
                    return @sizeOf(T);
                },
                // impl_array
                [2]u8, [4]u8, [8]u8, [12]u8, [16]u8, [32]u8, [33]u8 => {
                    writer.writeAll(self.value[0..]) catch unreachable;
                    return self.value.len;
                },
                []const u8 => {
                    const varInt = VarInt.init(@as(u64, @intCast(self.value.len)));
                    const len = try Encodable(VarInt).init(varInt).consensusEncode(writer);
                    _ = writer.writeAll(self.value) catch unreachable;
                    return len + self.value.len;
                },
                []u64, []const u64 => {
                    const vec = Vector(u64).init(self.allocator);
                    return vec.consensusEncode(writer);
                },
                Sha256D => {
                    return Encodable([32]u8).init(self.value.buf).consensusEncode(writer);
                },
                else => {
                    if (@hasDecl(T, "consensusEncode")) {
                        return self.value.consensusEncode(writer);
                    }
                    @compileError("Unsupported type: " ++ @typeName(T));
                },
            };
        }
    };
}

/// Decode an object from a byte slice
pub fn Decodable(comptime T: type) type {
    return struct {
        pub const Option = struct {
            allocator: ?std.mem.Allocator = null,
        };

        pub fn consensusDecode(option: DecoderOption, reader: Reader) Error!T {
            switch (T) {
                bool => {
                    const n = reader.readByte() catch {
                        return Error.IoError;
                    };
                    return n != 0;
                },
                u8, i8 => {
                    const n = reader.readByte() catch {
                        return Error.IoError;
                    };
                    return @as(T, @intCast(n));
                },
                u16, i16, u32, i32, u64, i64 => {
                    const n = reader.readInt(T, .little) catch {
                        return error.IoError;
                    };
                    return n;
                },

                // TODO add fix lenth check
                [2]u8, [4]u8, [8]u8, [12]u8, [16]u8, [32]u8, [33]u8 => {
                    // |len(VarInt) | data(slice) |
                    const varInt = try VarInt.consensusDecode(option, reader);
                    if (varInt.value > MAX_VEC_SIZE) {
                        return Error.OversizedVectorAllocation;
                    }
                    // the length of the data must be >= 1
                    std.debug.assert(varInt.value >= 1);
                    var result: T = undefined;
                    const n = reader.read(&result) catch {
                        return Error.IoError;
                    };
                    if (n != @sizeOf(T)) {
                        return Error.IoError;
                    }
                    return result;
                },
                Sha256D => {
                    const h = try Decodable([32]u8).consensusDecode(option, reader);
                    return Sha256D.initWithBuff(h);
                },
                []u8, []const u8 => {
                    // |len(VarInt) | data(slice) |
                    const varInt = try VarInt.consensusDecode(option, reader);
                    if (varInt.value > MAX_VEC_SIZE) {
                        return Error.OversizedVectorAllocation;
                    }
                    // the length of the data must be >= 1
                    std.debug.assert(varInt.value >= 1);

                    const data_ = option.allocator.?.alloc(u8, varInt.value) catch {
                        return Error.ParseFailed;
                    };
                    errdefer option.allocator.?.free(data_);
                    _ = reader.readAll(data_) catch {
                        return Error.ParseFailed;
                    };
                    return data_;
                },
                []u64 => {
                    var vec = try Vector(u64).consensusDecode(option, reader);
                    return vec.toOwned();
                },
                else => {
                    // CheckedData, VarInt
                    const has = @hasDecl(T, "consensusDecode");
                    if (has) {
                        return T.consensusDecode(option, reader);
                    }
                    @compileError("Unsupported type: " ++ @typeName(T));
                },
            }
        }
    };
}

fn sha2CheckSum(data: []const u8) [4]u8 {
    var engine = Sha256D.engine();
    var checksum: [32]u8 = undefined;
    engine.update(data);
    engine.finish(&checksum);
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

    /// 编码VarInt, consensus_encode(writer)
    pub fn consensusEncode(self: VarInt, writer: anytype) Error!usize {
        switch (self.value) {
            0...0xFC => {
                const n = @as(u8, @intCast(self.value));
                // 1 byte
                const dataLen = try Encodable(u8).init(n).consensusEncode(writer);
                std.debug.assert(dataLen == 1);
                return dataLen;
            },
            0xFD...0xFFFF => {
                writer.writeByte(0xFD) catch unreachable;
                const dataLen = try Encodable(u16).init(@intCast(self.value)).consensusEncode(writer);
                std.debug.assert(dataLen == 2);
                // 1 byte + 2 bytes
                return dataLen + 1;
            },
            0x10000...0xFFFFFFFF => {
                writer.writeByte(0xFE) catch unreachable;
                const dataLen = try Encodable(u32).init(@intCast(self.value)).consensusEncode(writer);
                std.debug.assert(dataLen == 4);
                // 1 byte + 4 bytes
                return dataLen + 1;
            },
            else => {
                writer.writeByte(0xFF) catch unreachable;
                const dataLen = try Encodable(u64).init(self.value).consensusEncode(writer);
                std.debug.assert(dataLen == 8);
                // 1 byte + 8 bytes
                return dataLen + 1;
            },
        }
    }

    /// 解码VarInt, consensus_decode(reader)
    pub fn consensusDecode(_: DecoderOption, reader: Reader) Error!VarInt {
        const n = reader.readByte() catch {
            return Error.IoError;
        };
        switch (n) {
            0xFF => {
                const x = reader.readInt(u64, .little) catch {
                    return Error.IoError;
                };
                if (x < 0x100000000) {
                    return Error.NonMinimalVarInt;
                }
                return VarInt.init(x);
            },
            0xFE => {
                const x = reader.readInt(u32, .little) catch {
                    return Error.IoError;
                };
                if (x < 0x10000) {
                    return Error.NonMinimalVarInt;
                }
                return VarInt.init(x);
            },
            0xFD => {
                const x = reader.readInt(u16, .little) catch {
                    return Error.IoError;
                };
                if (x < 0xFD) {
                    return Error.NonMinimalVarInt;
                }
                return VarInt.init(x);
            },
            else => return VarInt.init(n),
        }
    }
};

pub const CheckedData = struct {
    data: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: CheckedData) void {
        self.allocator.free(self.data);
    }

    pub fn consensusEncode(self: *const @This(), writer: anytype) !usize {
        const dataLen = @as(u32, @intCast(self.data.len));
        writer.writeInt(u32, dataLen, .little) catch unreachable;
        const checkSum = sha2CheckSum(self.data);
        _ = writer.writeAll(&checkSum) catch unreachable;
        _ = writer.writeAll(self.data) catch unreachable;
        return self.data.len + 8;
    }

    pub fn consensusDecode(option: DecoderOption, reader: Reader) !@This() {
        var allocator = option.allocator.?;
        const dataLen: u32 = reader.readInt(u32, .little) catch {
            return Error.IoError;
        };
        if (dataLen > MAX_VEC_SIZE) {
            return Error.OversizedVectorAllocation;
        }
        var checkSum: [4]u8 = [4]u8{ 0, 0, 0, 0 };
        const checkSumLen = reader.read(&checkSum) catch {
            return Error.IoError;
        };
        if (checkSumLen != 4) {
            return Error.IoError;
        }
        const data_ = allocator.alloc(u8, dataLen) catch {
            return Error.IoError;
        };
        errdefer allocator.free(data_);
        _ = reader.read(data_) catch {
            return Error.IoError;
        };
        return CheckedData{ .data = data_, .allocator = allocator };
    }
};

pub fn Vector(comptime T: type) type {
    return struct {
        vec: std.ArrayList(T),

        pub fn init(allocator: std.mem.Allocator) @This() {
            return .{ .vec = std.ArrayList(T).init(allocator) };
        }

        /// encode a vector of objects
        pub fn consensusEncode(self: *const @This(), writer: anytype) !usize {
            var len = 0;
            for (self.vec.items) |item| {
                len += try Encodable(T).init(item).consensusEncode(writer);
            }
            return len;
        }

        /// Decode a vector of objects
        pub fn consensusDecode(option: DecoderOption, reader: Reader) Error!@This() {
            const allocator = option.allocator.?;
            const varint = try VarInt.consensusDecode(option, reader);
            const len = varint.value;
            if (len > MAX_VEC_SIZE) {
                return Error.OversizedVectorAllocation;
            }
            const byteSize = len * @sizeOf(T);
            if (byteSize > MAX_VEC_SIZE) {
                return Error.OversizedVectorAllocation;
            }
            var result = std.ArrayList(T).init(allocator);
            errdefer result.deinit();
            const decoder = Decodable(T);
            for (0..len) |_| {
                const decoded = try decoder.consensusDecode(.{ .allocator = allocator }, reader);
                result.append(decoded) catch unreachable;
            }
            return .{ .vec = result };
        }

        fn toOwned(self: *@This()) []T {
            return self.vec.toOwnedSlice() catch unreachable;
        }
    };
}

fn hasFn(comptime a: type, fn_name: []const u8) bool {
    const T = @TypeOf(a);
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            inline for (info.fields) |field| {
                if (std.mem.eql(u8, field.name, fn_name)) {
                    return true;
                }
            }
            return false;
        },
        else => return false,
    }
}

fn testVarIntEncode(n: u8, x: []const u8) Error!VarInt {
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

fn testLenIsMaxVec(allocator: std.mem.Allocator, comptime T: type) !void {
    const varint = VarInt.init(@as(u64, @intCast(MAX_VEC_SIZE / @sizeOf(T))));
    const encoded = try serialize(allocator, varint);
    defer allocator.free(encoded);
    _ = deserializedVec(allocator, T, encoded) catch |err| {
        try std.testing.expect(err == Error.IoError);
        return;
    };
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
    var area = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer area.deinit();
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
            const got = try serialize(area.allocator(), arg);
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

test "serialize_strbuf_test" {
    const str: []const u8 = "Andrew";
    const encoded = try serialize(testing.allocator, str);
    defer testing.allocator.free(encoded);
    try testing.expect(std.mem.eql(u8, encoded, &[_]u8{ 6, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77 }));
}

test "deserialize_int_test" {
    // bool
    {
        _ = deserialize(bool, &[_]u8{ 58, 0 }) catch |err| {
            try testing.expect(err == error.ParseFailed);
        };
        _ = deserialize(bool, &[_]u8{58}) catch unreachable;
        _ = deserialize(bool, &[_]u8{1}) catch unreachable;
        _ = deserialize(bool, &[_]u8{0}) catch unreachable;
        _ = deserialize(bool, &[_]u8{ 0, 1 }) catch |err| {
            try testing.expect(err == error.ParseFailed);
        };
    }

    // u8
    {
        _ = deserialize(u8, &[_]u8{58}) catch unreachable;
    }

    // u16
    {
        const got = try deserialize(u16, &[_]u8{ 0x01, 0x02 });
        try testing.expectEqual(got, 0x0201);
        const got2 = try deserialize(u16, &[_]u8{ 0xAB, 0xCD });
        try testing.expectEqual(got2, 0xCDAB);
        const got3 = try deserialize(u16, &[_]u8{ 0xA0, 0x0D });
        try testing.expectEqual(got3, 0xDA0);
        _ = deserialize(u16, &[_]u8{1}) catch |err| {
            try testing.expect(err == error.IoError);
        };
    }
    // u32
    {
        const got = try deserialize(u32, &[_]u8{ 0xAB, 0xCD, 0, 0 });
        try testing.expectEqual(got, 0xCDAB);
        const got2 = try deserialize(u32, &[_]u8{ 0xA0, 0x0D, 0xAB, 0xCD });
        try testing.expectEqual(got2, 0xCDAB0DA0);
        _ = deserialize(u32, &[_]u8{ 1, 2, 3 }) catch |err| {
            try testing.expect(err == error.IoError);
        };

        const got3 = try deserialize(i32, &[_]u8{ 0xAB, 0xCD, 0, 0 });
        try testing.expectEqual(got3, 0xCDAB);
        const got4 = try deserialize(i32, &[_]u8{ 0xA0, 0x0D, 0xAB, 0x2D });
        try testing.expectEqual(got4, 0x2DAB0DA0);
        _ = deserialize(i32, &[_]u8{ 1, 2, 3 }) catch |err| {
            try testing.expect(err == error.IoError);
        };
    }

    // u64
    {
        const got = try deserialize(u64, &[_]u8{ 0xAB, 0xCD, 0, 0, 0, 0, 0, 0 });
        try testing.expectEqual(got, 0xCDAB);
        const got2 = try deserialize(u64, &[_]u8{ 0xA0, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99 });
        try testing.expectEqual(got2, 0x99000099CDAB0DA0);
        _ = deserialize(u64, &[_]u8{ 1, 2, 3, 4, 5, 6, 7 }) catch |err| {
            try testing.expect(err == error.IoError);
        };

        const got3 = try deserialize(i64, &[_]u8{ 0xAB, 0xCD, 0, 0, 0, 0, 0, 0 });
        try testing.expectEqual(got3, 0xCDAB);
        const got4 = try deserialize(i64, &[_]u8{ 0xA0, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99 });
        try testing.expectEqual(got4, -0x66ffff663254f260);
        _ = deserialize(i64, &[_]u8{ 1, 2, 3, 4, 5, 6, 7 }) catch |err| {
            try testing.expect(err == error.IoError);
        };
    }
}

test "deserialize_vec_test" {
    var area = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer area.deinit();
    const got = try deserializeWithAllocator(area.allocator(), []const u8, &[_]u8{ 3, 2, 3, 4 });
    try testing.expectEqualSlices(u8, got, &[_]u8{ 2, 3, 4 });
    _ = deserializeWithAllocator(area.allocator(), []const u8, &[_]u8{ 4, 2, 3, 4, 5, 6 }) catch |err| {
        testing.expect(err == error.ParseFailed) catch unreachable;
    };
    _ = deserializeWithAllocator(area.allocator(), []u64, &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0xa, 0xa, 0x3a }) catch |err| {
        testing.expect(err == error.OversizedVectorAllocation) catch unreachable;
    };

    // Check serialization that `if len > MAX_VEC_SIZE {return err}` isn't inclusive,
    // by making sure it fails with IO Error and not an `OversizedVectorAllocation` Error.
    {
        _ = deserializeWithAllocator(area.allocator(), CheckedData, serialize(area.allocator(), @as(u32, MAX_VEC_SIZE)) catch unreachable) catch |err| {
            try std.testing.expect(err == Error.IoError);
        };
        testLenIsMaxVec(area.allocator(), u8) catch unreachable;
        testLenIsMaxVec(area.allocator(), hashType.BlockHash) catch unreachable;
        testLenIsMaxVec(area.allocator(), hashType.FilterHash) catch unreachable;
        testLenIsMaxVec(area.allocator(), hashType.TxMerkleNode) catch unreachable;
        // test_len_is_max_vec::<Transaction>();
        // test_len_is_max_vec::<TxOut>();
        // test_len_is_max_vec::<TxIn>();
        // test_len_is_max_vec::<Inventory>();
        testLenIsMaxVec(area.allocator(), []const u8) catch unreachable;
        //  test_len_is_max_vec::<(u32, Address)>();
        testLenIsMaxVec(area.allocator(), u64) catch unreachable;
    }
}

test "deserialize_strbuf_test" {
    var area = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer area.deinit();
    const str = deserializeWithAllocator(area.allocator(), []const u8, &[_]u8{ 6, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77 }) catch unreachable;
    try testing.expect(std.mem.eql(u8, str, "Andrew"));
}

test "deserialize_checkeddata_test" {
    std.testing.log_level = .debug;
    var area = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer area.deinit();
    const checkSum = try deserializeWithAllocator(area.allocator(), CheckedData, &[_]u8{ 5, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5 });
    defer checkSum.deinit();
    try testing.expectEqualSlices(u8, checkSum.data, &[_]u8{ 1, 2, 3, 4, 5 });
}

test "serialization_round_trips" {
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    {
        const boolValue = random.boolean();
        const boolEncoded = try deserialize(bool, try serialize(allocator, boolValue));
        try testing.expectEqual(boolValue, boolEncoded);
    }
    // Test i8
    {
        const i8Value = random.int(i8);
        const i8Encoded = try deserialize(i8, try serialize(allocator, i8Value));
        try testing.expectEqual(i8Value, i8Encoded);
    }
    // Test u8
    {
        const u8Value = random.int(u8);
        const u8Encoded = try deserialize(u8, try serialize(allocator, u8Value));
        try testing.expectEqual(u8Value, u8Encoded);
    }
    // Test i16
    {
        const i16Value = random.int(i16);
        const i16Encoded = try deserialize(i16, try serialize(allocator, i16Value));
        try testing.expectEqual(i16Value, i16Encoded);
    }
    // Test u16
    {
        const u16Value = random.int(u16);
        const u16Encoded = try deserialize(u16, try serialize(allocator, u16Value));
        try testing.expectEqual(u16Value, u16Encoded);
    }
    // Test i32
    {
        const i32Value = random.int(i32);
        const i32Encoded = try deserialize(i32, try serialize(allocator, i32Value));
        try testing.expectEqual(i32Value, i32Encoded);
    }
    // Test u32
    {
        const u32Value = random.int(u32);
        const u32Encoded = try deserialize(u32, try serialize(allocator, u32Value));
        try testing.expectEqual(u32Value, u32Encoded);
    }
    // Test i64
    {
        const i64Value = random.int(i64);
        const i64Encoded = try deserialize(i64, try serialize(allocator, i64Value));
        try testing.expectEqual(i64Value, i64Encoded);
    }
    // Test u64
    {
        const u64Value = random.int(u64);
        const u64Encoded = try deserialize(u64, try serialize(allocator, u64Value));
        try testing.expectEqual(u64Value, u64Encoded);
    }
}

test "serialize_checked_data" {
    const data = CheckedData{ .data = &[_]u8{ 1, 2, 3, 4, 5 }, .allocator = testing.allocator };
    const encoded = try serialize(testing.allocator, data);
    defer testing.allocator.free(encoded);
    try testing.expect(std.mem.eql(u8, encoded, &[_]u8{ 5, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5 }));
    std.testing.log_level = .debug;
}

test "encodable" {
    var _i8 = Encodable(i8).init(1);
    var buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer buffer.deinit();
    const nsize = try _i8.consensusEncode(buffer.writer());
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
        _ = try Encodable(u16).init(original).consensusEncode(stream.writer());
        _ = try Encodable(u8).init(42).consensusEncode(stream.writer());

        const result = try deserializePartial(u16, buffer);
        try testing.expectEqual(original, result.value);
        try testing.expectEqual(@as(usize, 2), result.consumed);
    }
}

// // test {
// //     std.testing.refAllDecls(@This());
// //     _ = @import("Random/test.zig");
// // }

// test "is_struct" {
//     const MyStruct = struct {
//         field: u32,
//     };
//     try testing.expect(!hasFn(MyStruct, "deinit"));
//     try testing.expect(!hasFn(u32, "deinit"));
//     try testing.expect(!hasFn([]const u8, "deinit"));
//     try testing.expect(!hasFn(*u32, "deinit"));
// }
