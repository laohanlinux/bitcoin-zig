const local = @import("amount.zig");
const Amount = local.Amount;
const SignedAmount = local.SignedAmount;
const ParseAmountError = local.ParseAmountError;
const std = @import("std");

test "add_sub_mul_div" {
    const sat = Amount.fromSat;
    const ssat = SignedAmount.fromSat;
    try std.testing.expectEqual(try sat(15).add(sat(15)), sat(30));
    try std.testing.expectEqual(try sat(15).sub(sat(15)), sat(0));
    try std.testing.expectEqual(try sat(14).mul(@as(u64, 3)), sat(42));
    try std.testing.expectEqual(try sat(14).div(@as(u64, 2)), sat(7));
    try std.testing.expectEqual(try sat(14).rem(@as(u64, 3)), sat(2));
    try std.testing.expectEqual(try ssat(15).sub(@as(i64, 20)), ssat(-5));
    try std.testing.expectEqual(try ssat(-14).mul(@as(i64, 3)), ssat(-42));
    try std.testing.expectEqual(try ssat(-14).div(@as(i64, 2)), ssat(-7));
    try std.testing.expectEqual(try ssat(-14).rem(@as(i64, 3)), ssat(-2));

    var b = ssat(-5);
    try b.addAssign(@as(i64, 13));
    try std.testing.expectEqual(b, ssat(8));
    try b.subAssign(@as(i64, 3));
    try std.testing.expectEqual(b, ssat(5));
}
