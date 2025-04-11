const sha256d = @import("hashes").engine.HashEngine(.sha256d);
const base58 = @import("base58");
const std = @import("std");

pub const Error = error{
    TooShort,
    BadCheckSum,
} || base58.EncoderError || base58.DecoderError;

pub fn encode(allocator: std.mem.Allocator, source: []const u8) Error![]u8 {
    var encoder = base58.Encoder.init(.{});
    const encoded = encoder.encodeAlloc(allocator, source) catch unreachable;
    return encoded;
}

pub fn decode(allocator: std.mem.Allocator, encoded: []const u8) Error![]u8 {
    var decoder = base58.Decoder.init(.{});
    const decoded = try decoder.decodeAlloc(allocator, encoded);
    return decoded;
}

/// Obtain a string with the base58check encoding of a slice
/// (Tack the first 4 256-digits of the object's Bitcoin hash onto the end.)
/// TODO Optimize this
pub fn checkEncodeSliceToFmt(allocator: std.mem.Allocator, slice: []const u8) Error![]u8 {
    var outer: [32]u8 = undefined;
    {
        var hasher = sha256d.init(.{});
        hasher.update(slice);
        hasher.finish(&outer);
    }
    var combined = try allocator.alloc(u8, slice.len + 4);
    @memcpy(combined[0..slice.len], slice);
    @memcpy(combined[slice.len..], outer[0..4]);
    defer allocator.free(combined);
    return encode(allocator, combined);
}

/// Decode a base58check-encoded string
/// Optimized for the case where the string is a valid base58check string
pub fn fromCheck(allocator: std.mem.Allocator, encoded: []const u8) Error![]u8 {
    var decoder = base58.Decoder.init(.{});
    const decoded = try decoder.decodeAlloc(allocator, encoded);
    defer allocator.free(decoded);
    if (decoded.len < 4) {
        return Error.TooShort;
    }
    const ckStart = decoded.len - 4;
    const ck = decoded[ckStart..];
    var outer: [32]u8 = undefined;
    var hasher = sha256d.init(.{});
    hasher.update(decoded[0..ckStart]);
    hasher.finish(&outer);
    if (!std.mem.eql(u8, ck, outer[0..4])) {
        return Error.BadCheckSum;
    }
    // Copy the decoded bytes to a new buffer
    const result = allocator.alloc(u8, ckStart) catch unreachable;
    @memcpy(result, decoded[0..ckStart]);
    return result;
}

test "should decodeAlloc value correctly" {
    var area = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer area.deinit();

    const encoded = try encode(area.allocator(), &[_]u8{0});
    try std.testing.expectEqualSlices(u8, encoded, "1");
    const encoded2 = try encode(area.allocator(), &[_]u8{1});
    try std.testing.expectEqualSlices(u8, encoded2, "2");
    const encoded3 = try encode(area.allocator(), &[_]u8{58});
    try std.testing.expectEqualSlices(u8, encoded3, "21");
    const encoded4 = try encode(area.allocator(), &[_]u8{ 13, 36 });
    try std.testing.expectEqualSlices(u8, encoded4, "211");
    const encoded5 = try encode(area.allocator(), &[_]u8{ 0, 13, 36 });
    try std.testing.expectEqualSlices(u8, encoded5, "1211");
    const encoded6 = try encode(area.allocator(), &[_]u8{ 0, 0, 0, 0, 13, 36 });
    try std.testing.expectEqualSlices(u8, encoded6, "1111211");

    // long input
    const long_input = "BitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoin";
    const encoded7 = try encode(area.allocator(), long_input[0..]);
    try std.testing.expectEqualSlices(u8, encoded7, "ZqC5ZdfpZRi7fjA8hbhX5pEE96MdH9hEaC1YouxscPtbJF16qVWksHWR4wwvx7MotFcs2ChbJqK8KJ9XwZznwWn1JFDhhTmGo9v6GjAVikzCsBWZehu7bm22xL8b5zBR5AsBygYRwbFJsNwNkjpyFuDKwmsUTKvkULCvucPJrN5QUdxpGakhqkZFL7RU4yT");

    // addresses
    const addr = [_]u8{ 0, 248, 145, 115, 3, 191, 168, 239, 36, 242, 146, 232, 250, 20, 25, 178, 4, 96, 186, 6, 77 };
    const encoded8 = try checkEncodeSliceToFmt(area.allocator(), addr[0..]);
    defer area.allocator().free(encoded8);
    try std.testing.expectEqualSlices(u8, encoded8, "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH");
}

test "test_base58_decode" {
    // Basics
    var area = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer area.deinit();
    try std.testing.expectEqualSlices(u8, try decode(area.allocator(), "1"), &[_]u8{0});
    try std.testing.expectEqualSlices(u8, try decode(area.allocator(), "2"), &[_]u8{1});
    try std.testing.expectEqualSlices(u8, try decode(area.allocator(), "21"), &[_]u8{58});
    try std.testing.expectEqualSlices(u8, try decode(area.allocator(), "211"), &[_]u8{ 13, 36 });

    // Leading zeros
    try std.testing.expectEqualSlices(u8, try decode(area.allocator(), "1211"), &[_]u8{ 0, 13, 36 });
    try std.testing.expectEqualSlices(u8, try decode(area.allocator(), "111211"), &[_]u8{ 0, 0, 0, 13, 36 });
    // Addresses
    const addr = [_]u8{ 0, 248, 145, 115, 3, 191, 168, 239, 36, 242, 146, 232, 250, 20, 25, 178, 4, 96, 186, 6, 77 };
    try std.testing.expectEqualSlices(u8, try fromCheck(area.allocator(), "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH"), addr[0..]);
    // Non Base58 char.
    try std.testing.expectError(base58.DecoderError.NonAsciiCharacter, fromCheck(area.allocator(), "¢"));
}

test "test_base58_roundtrip" {
    var area = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer area.deinit();
    const s = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs";
    const v = try fromCheck(area.allocator(), s);
    try std.testing.expectEqualSlices(u8, try checkEncodeSliceToFmt(area.allocator(), v), s);
    const v2 = try fromCheck(area.allocator(), try checkEncodeSliceToFmt(area.allocator(), v));
    try std.testing.expectEqualSlices(u8, v, v2);

    // Check that empty slice passes roundtrip.
    const v3 = try fromCheck(area.allocator(), try checkEncodeSliceToFmt(area.allocator(), &[_]u8{}));
    try std.testing.expectEqualSlices(u8, v3, &[_]u8{});
    // Check that `len > 4` is enforced.
    try std.testing.expectError(Error.TooShort, fromCheck(area.allocator(), try encode(area.allocator(), &[_]u8{ 1, 2, 3 })));
}
