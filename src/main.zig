const std = @import("std");
const base58 = @import("./base58.zig");
const allocator = std.heap.page_allocator;
// const ripemd160 = @import("./libcrypto/ripemd160.zig");
const crypto = @import("./libcrypto/crypto.zig");
const script = @import("./blockdata/script/script.zig");
const instr = @import("./blockdata/script/instruction.zig");
const script_lib = @import("./blockdata/script/lib.zig");

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

    {
        {
            const instruction = instr.Instruction{ .op = script.OpCodeType.OP_0 };
            const opType = instruction.opcode();
            std.debug.print("{any}\n", .{opType});
        }

        {
            var instruction = instr.Instruction{ .pushBytes = std.ArrayList(u8).init(allocator) };
            defer instruction.deinit();
            instruction.push_bytes("abc");
            const bytes = instruction.bytes().?;
            std.debug.print("{s}\n", .{bytes});
        }

        {
            const v = .{ 0x1, 0x2, 0x3 };
            const n = script_lib.read_scriptint_non_minimal(&v) catch unreachable;
            std.debug.print("{d}\n", .{n});
        }
    }
    {
        const num = try script_lib.read_scriptint_non_minimal(&[_]u8{ 0xff, 0xff, 0xff, 0x00 });
        std.debug.print("number=> {}\n", .{num});
    }

    {
        if (script_lib.readScriptBool(&[_]u8{})) {
            @panic("it should be false");
        }
        if (script_lib.readScriptBool(&[_]u8{0x00})) {
            @panic("it should be false");
        }
        if (!script_lib.readScriptBool(&[_]u8{0x01})) {
            @panic("it should be true");
        }
        if (script_lib.readScriptBool(&[_]u8{0x80})) {
            @panic("it should be false");
        }
        if (!script_lib.readScriptBool(&[_]u8{ 0x80, 0x01 })) {
            @panic("it should be true");
        }
        if (!script_lib.readScriptBool(&[_]u8{ 0x00, 0x81 })) {
            @panic("it should be true");
        }

        std.debug.print("pass readScriptBool\n", .{});
    }
    try bw.flush(); // don't forget to flush!
}

// test "simple test" {
//     var list = std.ArrayList(i32).init(std.testing.allocator);
//     defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
//     try list.append(42);
//     try std.testing.expectEqual(@as(i32, 42), list.pop());
// }
