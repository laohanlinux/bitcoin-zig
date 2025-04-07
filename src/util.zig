const std = @import("std");

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

test "print_type" {
    const MAX_VEC_SIZE: usize = 4_000_000;
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    var writer = buf.writer();
    try writer.writeInt(u32, MAX_VEC_SIZE, .little);
    std.debug.print("buf: {any}\n", .{buf.toOwnedSlice() catch unreachable});
}
