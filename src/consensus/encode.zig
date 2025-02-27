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
const mem = std.mem;
const math = std.math;
const testing = std.testing;

/// Encoding error type
pub const Error = error{
    IoError,
    PsbtError,
    UnexpectedNetworkMagic,
    OversizedVectorAllocation,
    InvalidChecksum,
    NonMinimalVarInt,
    UnknownNetworkMagic,
    ParseFailed,
    UnsupportedSegwitFlag,
    UnrecognizedNetworkCommand,
    UnknownInventoryType,
};

/// A variable-length unsigned integer
pub const VarInt = struct {
    value: u64,

    /// Gets the length of this VarInt when encoded
    pub fn getEncodedLength(self: VarInt) usize {
        return switch (self.value) {
            0...0xFC => 1,
            0xFD...0xFFFF => 3,
            0x10000...0xFFFFFFFF => 5,
            else => 9,
        };
    }
};

/// Data which must be preceded by a 4-byte checksum
pub const CheckedData = struct {
    data: []const u8,
};

// // Helper function to calculate double-SHA256 checksum
// fn sha2Checksum(data: []const u8) [4]u8 {
//     // const hash = sha256d.hash(data);
//     // return .{ hash[0], hash[1], hash[2], hash[3] };
// }

const DataType = union(enum) {
    Int,
    U8,
    U16,
    U32,
    U64,
    U128,
    I8,
    I16,
    I32,
    I64,
};

pub fn ConsensusEncDec(data: DataType) type {
    return struct {
        data: DataType,
        allocator: std.mem.Allocator,

        pub fn encode(self: @This()) ![]u8 {
            switch (data) {
                .Int => {
                    return self.data.encode(self.allocator);
                },
                .U8 => {
                    return self.data.encode(self.allocator);
                },
                .U16 => {
                    return self.data.encode(self.allocator);
                },
                .U32 => {
                    return self.data.encode(self.allocator);
                },
                .U64 => {
                    return self.data.encode(self.allocator);
                },
                .U128 => {
                    return self.data.encode(self.allocator);
                },
                .I8 => {
                    return self.data.encode(self.allocator);
                },
                .I16 => {
                    return self.data.encode(self.allocator);
                },
                .I32 => {
                    return self.data.encode(self.allocator);
                },
                .I64 => {
                    return self.data.encode(self.allocator);
                },
            }
        }

        pub fn decode(self: @This()) !DataType {
            switch (data) {
                .Int => {
                    return self.data.decode(self.allocator);
                },
                .U8 => {
                    return self.data.decode(self.allocator);
                },
                .U16 => {
                    return self.data.decode(self.allocator);
                },
                .U32 => {
                    return self.data.decode(self.allocator);
                },
                .U64 => {
                    return self.data.decode(self.allocator);
                },
                .I8 => {
                    return self.data.decode(self.allocator);
                },
                .I16 => {
                    return self.data.decode(self.allocator);
                },
                .I32 => {
                    return self.data.decode(self.allocator);
                },
                .I64 => {
                    return self.data.decode(self.allocator);
                },
            }
        }
    };
}
