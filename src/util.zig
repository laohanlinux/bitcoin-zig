const std = @import("std");

test "print_type" {
    const MAX_VEC_SIZE: usize = 4_000_000;
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    var writer = buf.writer();
    try writer.writeInt(u32, MAX_VEC_SIZE, .little);
    std.debug.print("buf: {any}\n", .{buf.toOwnedSlice() catch unreachable});
}
