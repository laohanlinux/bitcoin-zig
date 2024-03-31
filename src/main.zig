const std = @import("std");
const base58 = @import("./base58.zig");
const allocator = std.heap.page_allocator;
const ripemd160 = @import("./libcrypto/ripemd160.zig");
const crypto = @import("./libcrypto/crypto.zig");
pub fn main() !void {
    // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});

    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    var someBytes = [4]u8{ 10, 20, 30, 40 };
    var encoder = base58.Encoder58.init();
    const encodedStr = try encoder.encode(&someBytes);
    defer encoder.define();
    std.log.debug("encoded value: {s}", .{encodedStr});
    var original = [32]u8{
        57,  54,  18,  6,   106, 202, 13,  245, 224, 235, 33,  252, 254,
        251, 161, 17,  248, 108, 25,  214, 169, 154, 91,  101, 17,  121,
        235, 82,  175, 197, 144, 145,
    };
    //b58.Decoder.decodeAlloc(self: *const Self, allocator: std.mem.Allocator, encoded: []const u8)
    const encodedVal = "4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa";

    var decoder = base58.Decoder58.init(encodedVal);
    const decodedValue = decoder.decodeAlloc(allocator) catch unreachable;
    defer allocator.free(decodedValue);
    if (std.mem.eql(u8, decodedValue, &original) == false) {
        @panic("");
    }
    try bw.flush(); // don't forget to flush!
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
