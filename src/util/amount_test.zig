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
    try b.mulAssign(@as(i64, 6));
    try std.testing.expectEqual(b, ssat(30));
    try b.divAssign(@as(i64, 3));
    try std.testing.expectEqual(b, ssat(10));
    try b.remAssign(@as(i64, 3));
    try std.testing.expectEqual(b, ssat(1));
    // panic on overflow
}

test "checked_arithmetic" {
    const sat = Amount.fromSat;
    const ssat = SignedAmount.fromSat;
    try std.testing.expectEqual(sat(42).checkedAdd(@as(u64, 1)).?, sat(43));
    try std.testing.expectEqual(SignedAmount.maxValue().checkedAdd(ssat(1)) == null, true);
    try std.testing.expectEqual(SignedAmount.minValue().checkedSub(ssat(1)) == null, true);

    try std.testing.expectEqual(sat(5).checkedSub(sat(3)).?, sat(2));
    try std.testing.expectEqual(sat(5).checkedSub(sat(6)) == null, true);
    try std.testing.expectEqual(ssat(5).checkedSub(ssat(6)).?, ssat(-1));
    try std.testing.expectEqual(sat(5).checkedRem(@as(u64, 2)), sat(1));

    // integer division
    try std.testing.expectEqual(sat(5).checkedDiv(@as(u64, 2)), sat(2));
    try std.testing.expectEqual(ssat(-6).checkedDiv(@as(i64, 2)), ssat(-3));

    try std.testing.expectEqual(ssat(-5).positiveSub(ssat(3)) == null, true);
    try std.testing.expectEqual(ssat(5).positiveSub(ssat(-3)) == null, true);
    try std.testing.expectEqual(ssat(3).positiveSub(ssat(5)) == null, true);
    try std.testing.expectEqual(ssat(3).positiveSub(ssat(3)).?, ssat(0));
    try std.testing.expectEqual(ssat(5).positiveSub(ssat(3)).?, ssat(2));
}

test "floating_point" {
    const f = Amount.fromFloatIn;
    const sf = SignedAmount.fromFloatIn;
    const sat = Amount.fromSat;
    const ssat = SignedAmount.fromSat;

    try std.testing.expectEqual(try f(11.22, .bitcoin), sat(1122000000));
    try std.testing.expectEqual(try sf(-11.22, .milliBitcoin), ssat(-1122000));
    try std.testing.expectEqual(try f(11.22, .bit), sat(1122));
    try std.testing.expectEqual(try sf(-1000.0, .milliSatoshi), ssat(-1));
    try std.testing.expectEqual(try f(0.0001234, .bitcoin), sat(12340));
    try std.testing.expectEqual(try sf(-0.00012345, .bitcoin), ssat(-12345));

    try std.testing.expectError(ParseAmountError.Negative, f(-100.0, .bitcoin));
    try std.testing.expectError(ParseAmountError.TooPrecise, f(11.22, .satoshi));
    try std.testing.expectError(ParseAmountError.TooPrecise, sf(-100.0, .milliSatoshi));
    try std.testing.expectError(ParseAmountError.TooPrecise, f(42.123456781, .bitcoin));
    try std.testing.expectError(ParseAmountError.TooBig, sf(-184467440738.0, .bitcoin));
}
