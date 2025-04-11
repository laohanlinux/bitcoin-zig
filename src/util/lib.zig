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
