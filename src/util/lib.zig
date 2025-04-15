const std = @import("std");
pub const key = @import("key.zig");
pub const b58 = @import("b58.zig");
pub const bech32 = @import("bech32.zig");

/// Check if a type has a function with the given name.
pub fn hasFn(comptime a: type, fn_name: []const u8) bool {
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

pub inline fn tU64(t: u64) u64 {
    return t;
}

pub inline fn tI64(t: i64) i64 {
    return t;
}

pub inline fn tU32(t: u32) u32 {
    return t;
}

pub inline fn tI32(t: i32) i32 {
    return t;
}

test "toU64" {
    try std.testing.expect(tU64(100) == 100);
    try std.testing.expect(tU64(100.0) == 100);
    try std.testing.expect(tI64(100) == 100);
    try std.testing.expect(tI64(100.0) == 100);
    try std.testing.expect(tU32(100) == 100);
    try std.testing.expect(tU32(100.0) == 100);
    try std.testing.expect(tI32(100) == 100);
    try std.testing.expect(tI32(100.0) == 100);
}
