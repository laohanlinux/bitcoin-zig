const std = @import("std");
const testing = std.testing;

export fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "basic add functionality" {
    // try testing.expect(add(3, 7) == 10);
    // const privateKey = try util.PrivateKey.fromWif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");
    // const publicKey = privateKey.publicKey();
    // const publicKeyBytes = try publicKey.toBytes(std.testing.allocator);
    // try std.testing.expectEqualSlices(u8, publicKeyBytes, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
}
