const std = @import("std");
const crypto = std.crypto;
const Ripemd160 = @import("ripemd160.zig").Ripemd160;

/// Hash160 is a combination of SHA-256 and RIPEMD-160 hash functions.
/// It first applies SHA-256 on the input and then applies RIPEMD-160 on the result.
/// This is commonly used in Bitcoin for address generation.
/// Hash160(x) = RIPEMD-160(SHA-256(x))
pub fn hash160(input: []const u8) ![20]u8 {
    // First, apply SHA-256
    var sha256_output: [32]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(input, &sha256_output, .{});

    // Then, apply RIPEMD-160 on the SHA-256 result
    const ripemd160_hash = Ripemd160.hash(&sha256_output);

    return ripemd160_hash.bytes;
}

test "hash160" {
    const message = "The quick brown fox jumps over the lazy dog";

    // Apply hash160
    var result = try hash160(message);

    // Convert the hash to a hexadecimal string for comparison
    var hex_buf: [40]u8 = undefined; // 20 bytes × 2 hex chars per byte
    _ = try std.fmt.bufPrint(&hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(&result)});

    // Expected result (can be verified with external tools)
    const expected = "0e3397b4abc7a382b3ea2365883c3c7ca5f07600";

    try std.testing.expectEqualSlices(u8, expected, &hex_buf);
}
