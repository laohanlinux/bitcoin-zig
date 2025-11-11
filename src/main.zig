const std = @import("std");

pub fn main() !void {
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});

    // 简化示例：也用 debug.print 输出运行提示
    std.debug.print("Run `zig build test` to run the tests.\n", .{});
}

test "simple test" {
    var list: std.ArrayList(i32) = .empty;
    defer list.deinit(std.testing.allocator); // try commenting this out and see if zig detects the memory leak!
    try list.append(std.testing.allocator, 42);
    const item = list.pop().?;
    std.debug.print("item is {}\n", .{item});
}
