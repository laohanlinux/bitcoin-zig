// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Amounts
//!
//! This module mainly introduces the [Amount] and [SignedAmount] types.
//! We refer to the documentation on the types for more information.
//!
const std = @import("std");
const fmt = std.fmt;
const math = std.math;

/// Denominations in which amounts can be expressed
pub const Denomination = enum {
    /// BTC
    bitcoin,
    /// mBTC
    milliBitcoin,
    /// uBTC
    microBitcoin,
    /// bits
    bit,
    /// satoshi
    satoshi,
    /// msat
    milliSatoshi,

    /// Get the number of decimal places relative to a satoshi
    pub fn precision(self: Denomination) i32 {
        return switch (self) {
            .bitcoin => -8, // 1 BTC = 100,000,000 satoshis
            .milliBitcoin => -5, // 1 mBTC = 100,000 satoshis
            .microBitcoin => -2, // 1 uBTC = 100 satoshis
            .bit => -2, // 1 bit = 100 satoshis
            .satoshi => 0, // 1 satoshi = 1 satoshi
            .milliSatoshi => 3, // 1 msat = 0.001 satoshis
        };
    }

    /// Convert denomination to string representation
    pub inline fn toString(self: Denomination) []const u8 {
        return switch (self) {
            .bitcoin => "BTC",
            .milliBitcoin => "mBTC",
            .microBitcoin => "uBTC",
            .bit => "bits",
            .satoshi => "satoshi",
            .milliSatoshi => "msat",
        };
    }

    /// Parse denomination from string
    pub inline fn fromString(str: []const u8) !Denomination {
        if (std.mem.eql(u8, str, "BTC")) return .bitcoin;
        if (std.mem.eql(u8, str, "mBTC")) return .milliBitcoin;
        if (std.mem.eql(u8, str, "uBTC")) return .microBitcoin;
        if (std.mem.eql(u8, str, "bits")) return .bit;
        if (std.mem.eql(u8, str, "satoshi") or std.mem.eql(u8, str, "sat")) return .satoshi;
        if (std.mem.eql(u8, str, "msat")) return .milliSatoshi;
        return error.UnknownDenomination;
    }
};

/// Errors that can occur during amount parsing
pub const ParseAmountError = error{
    /// Amount is negative
    Negative,
    /// Amount is too big to fit inside the type
    TooBig,
    /// Amount has higher precision than supported
    TooPrecise,
    /// Invalid number format
    InvalidFormat,
    /// Input string was too large
    InputTooLarge,
    /// Invalid character in input
    InvalidCharacter,
    /// Unknown denomination
    UnknownDenomination,
    /// Overflow denomination
    Overflow,
};

/// Format parse amount error string.
pub inline fn formatParseAmountError(err: ParseAmountError) ![]u8 {
    return switch (err) {
        .UnknownDenomination => "unknown denomination",
        .Negative => "amount is negative",
        .TooBig => "amount is too big",
        .TooPrecise => "amount has a too high precision",
        .InvalidFormat => "invalid number format",
        .InputTooLarge => "input string was too large",
        .InvalidCharacter => "invalid character in input",
    };
}

/// Check if a string has too much precision for given decimal places
/// str is the string to check, precision is the number of decimal places
fn isTooPrecise(str: []const u8, precision: usize) bool {
    // If there is a decimal point, it is too precise
    if (std.mem.indexOf(u8, str, ".") != null) return true;
    // If the precision is greater than the length of the string, it is too precise
    if (precision >= str.len) return true;
    // Check if the last precision digits are zeroes
    var i: usize = 0;
    while (i < precision) : (i += 1) {
        if (str[str.len - 1 - i] != '0') return true;
    }
    return false;
}

/// Parse decimal string in given denomination into satoshis and sign
fn parseSignedToSatoshi(str: []const u8, denom: Denomination) ParseAmountError!struct { bool, u64 } {
    if (str.len == 0) return ParseAmountError.InvalidFormat;
    if (str.len > 50) return ParseAmountError.InputTooLarge;

    const isNegative = str[0] == '-';
    var valueStr = if (isNegative) str[1..] else str;

    if (valueStr.len == 0) return ParseAmountError.InvalidFormat;

    // Calculate maximum allowed decimals
    // The difference in precision between native (satoshi)
    // and desired denomination.
    const precisionDiff = -denom.precision();

    const maxDecimals = if (precisionDiff < 0) blk: { // the condition is true when denom is milliSatoshi
        // If precision diff is negative, this means we are parsing
        // into a less precise amount. That is not allowed unless
        // there are no decimals and the last digits are zeroes as
        // many as the difference in precision.
        // Less precise denomination
        const lastN = @as(usize, @abs(precisionDiff));
        // milliSatoshi --> convert to satoshi
        // 1 msat = 0.001 satoshi, so we need to check if the last 3 digits are zeroes and no existing decimal point
        // 1000 msat = 1 satoshi (satoshi is the smallest denomination, msat is only used for some sence, like lightning network)
        if (isTooPrecise(valueStr, lastN)) return ParseAmountError.TooPrecise;
        valueStr = valueStr[0..(valueStr.len - lastN)]; // ignore the last N digits, just like value / n*zeros
        break :blk 0;
    } else precisionDiff; // the condition is true when denom is not milliSatoshi

    // Track the number of decimal places
    var decimals: ?usize = null;
    // The value in satoshis
    var value: u64 = 0;

    for (valueStr) |c| {
        switch (c) {
            '0'...'9' => {
                // value = 10 * value + digit
                const digit = c - '0';
                value = math.mul(u64, value, 10) catch return ParseAmountError.TooBig;
                value = math.add(u64, value, digit) catch return ParseAmountError.TooBig;

                // Track decimal places
                if (decimals) |d| {
                    if (d >= maxDecimals) return ParseAmountError.TooPrecise;
                    decimals = d + 1; // Warning: the condition is very important, it is used to check if the number of decimal places is too big
                    // example: 123.456, maxDecimals = 2, d = 2, d + 1 = 3, 3 >= 2, 0.006 will be ingore, so it is too precise
                    // 1BTC = 100,000,000 satoshi, so 0.00_000_000_1 BTC = 0.1 sat, satoshi is the smallest denomination, so it is too precise, 0.1sat is ignored
                }
            },
            '.' => { // Warning:  the condition  maybe is true when denom is not milliSatoshi
                if (decimals != null) return ParseAmountError.InvalidFormat;
                decimals = 0;
            },
            else => return ParseAmountError.InvalidCharacter,
        }
    }

    // Scale by remaining decimal places
    const scale = @as(usize, @intCast(maxDecimals)) - @as(usize, @intCast(decimals orelse 0));
    var i: usize = 0;
    while (i < scale) : (i += 1) {
        value = math.mul(u64, value, 10) catch return ParseAmountError.TooBig;
    }

    return .{ isNegative, value };
}

/// Format satoshi amount in given denomination
pub fn formatSatoshiIn(
    allocator: std.mem.Allocator,
    satoshi: u64,
    negative: bool,
    denom: Denomination,
) ParseAmountError![]u8 {
    var buf = std.ArrayList(u8).initCapacity(allocator, 32) catch unreachable;
    errdefer buf.deinit();
    if (negative) {
        buf.append('-') catch unreachable;
    }

    const precision = denom.precision();
    std.debug.print("satoshi: {d}, precision: {d}\n", .{ satoshi, precision });
    switch (std.math.order(precision, 0)) {
        .gt => {
            std.debug.print("precision: {d}\n", .{precision});
            // Add zeros at end
            const width = @as(usize, @intCast(precision));
            const zeroPadded = [_]u8{'0'} ** 8;
            std.debug.assert(width <= 8);
            std.fmt.format(buf.writer(), "{d}{s}", .{ satoshi, zeroPadded[0..width] }) catch unreachable;
        },
        .lt => {
            // Insert decimal point
            const nbDecimals = @as(u64, @abs(precision));
            // Convert number to string with padding
            const formatStr = std.fmt.allocPrint(allocator, "{d}", .{satoshi}) catch unreachable;
            defer allocator.free(formatStr);
            if (formatStr.len <= nbDecimals) {
                buf.appendSlice("0.") catch unreachable;
                buf.appendNTimes('0', (nbDecimals - formatStr.len)) catch unreachable;
                buf.appendSlice(formatStr) catch unreachable;
            } else {
                const integerPart = formatStr[0 .. formatStr.len - nbDecimals];
                const decimalPart = formatStr[formatStr.len - nbDecimals ..];
                buf.appendSlice(integerPart) catch unreachable;
                buf.append('.') catch unreachable;
                buf.appendSlice(decimalPart) catch unreachable;
            }
        },
        .eq => {
            fmt.format(buf.writer(), "{d}", .{satoshi}) catch unreachable;
        },
    }

    const result = buf.toOwnedSlice() catch unreachable;
    buf.deinit();
    return result;
}

/// Amount type that can be used to express Bitcoin amounts
pub const Amount = struct {
    value: u64, // satoshis

    /// Zero amount
    pub const ZERO = Amount{ .value = 0 };
    /// One satoshi
    pub const ONE_SAT = Amount{ .value = 1 };
    /// One bitcoin
    pub const ONE_BTC = Amount{ .value = 100_000_000 };

    /// Create amount from satoshis
    pub fn fromSat(satoshi: u64) Amount {
        return .{ .value = satoshi };
    }

    /// Get amount in satoshis
    pub fn asSat(self: Amount) u64 {
        return self.value;
    }

    /// Maximum value
    pub fn maxValue() Amount {
        return .{ .value = math.maxInt(u64) };
    }

    /// Minimum value
    pub fn minValue() Amount {
        return .{ .value = 0 };
    }

    /// Convert from BTC value
    pub fn fromBtc(btc: f64) !Amount {
        return fromFloatIn(btc, .bitcoin);
    }

    /// Convert to BTC value
    pub inline fn asBtc(self: Amount, allocator: std.mem.Allocator) ParseAmountError!f64 {
        return self.toFloatIn(allocator, .bitcoin);
    }

    /// Parse amount string with denomination
    pub fn fromString(str: []const u8, denom: Denomination) ParseAmountError!Amount {
        const result = try parseSignedToSatoshi(str, denom);
        const negative: bool = result[0];
        const satoshi: u64 = result[1];
        if (negative) return ParseAmountError.Negative;
        if (satoshi > math.maxInt(i64)) return ParseAmountError.TooBig;
        return Amount{ .value = satoshi };
    }

    /// Parses amounts with denomination suffix like they are produced with
    /// [to_string_with_denomination] or with [fmt::Display].
    /// If you want to parse only the amount without the denomination,
    /// use [from_str_in].
    pub fn fromStrWithDenomination(str: []const u8) ParseAmountError!Amount {
        const split = std.mem.splitSequence(u8, str, ' ');
        const amt_str = split.next() orelse return ParseAmountError.InvalidFormat;
        const denom_str = split.next() orelse return ParseAmountError.InvalidFormat;
        const denom = try Denomination.fromString(denom_str);
        return fromString(amt_str, denom);
    }

    /// Format amount in given denomination
    pub fn formatValue(self: Amount, allocator: std.mem.Allocator, denom: Denomination) ParseAmountError![]u8 {
        return formatSatoshiIn(self.value, false, allocator, denom);
    }

    /// Format amount with denomination
    pub fn toString(self: Amount, allocator: std.mem.Allocator, denom: Denomination) ParseAmountError![]u8 {
        const value = try self.formatValue(allocator, denom);
        defer allocator.free(value);

        return fmt.allocPrint(allocator, "{s} {s}", .{ value, denom.toString() }) catch unreachable;
    }

    /// Convert to float in given denomination
    pub inline fn toFloatIn(self: Amount, allocator: std.mem.Allocator, denom: Denomination) ParseAmountError!f64 {
        const str = try self.toStringIn(allocator, denom);
        return std.fmt.parseFloat(f64, str) catch unreachable;
    }

    /// Convert to string in given denomination
    pub inline fn toStringIn(self: Amount, allocator: std.mem.Allocator, denom: Denomination) ParseAmountError![]u8 {
        const str = try self.fmtValueIn(allocator, denom);
        return str;
    }

    pub fn fmtValueIn(self: Amount, allocator: std.mem.Allocator, denom: Denomination) ParseAmountError![]u8 {
        return formatSatoshiIn(allocator, self.value, false, denom);
    }

    /// Convert from float in given denomination
    pub fn fromFloatIn(value: f64, denom: Denomination) ParseAmountError!Amount {
        if (value < 0.0) return ParseAmountError.Negative;

        // Convert to string for safe parsing
        var buf: [32]u8 = undefined;
        const str = std.fmt.bufPrint(&buf, "{d}", .{value}) catch unreachable;
        return fromString(str, denom);
    }

    // Some arithmetic that doesn't fit in `std::ops` traits.

    /// Checked addition.
    /// Returns [None] if overflow occurred.
    pub fn checkedAdd(self: Amount, other: anytype) ?Amount {
        switch (@TypeOf(other)) {
            u64 => {
                const o = math.add(u64, self.value, other) catch return null;
                return .{ .value = o };
            },
            Amount => {
                const o = math.add(u64, self.value, other.value) catch return null;
                return .{ .value = o };
            },
            else => {
                @compileError("Expected u64 or Amount");
            },
        }
    }

    /// Checked subtraction.
    /// Returns [None] if overflow occurred.
    pub fn checkedSub(self: Amount, other: anytype) ?Amount {
        switch (@TypeOf(other)) {
            u64 => {
                const o = math.sub(u64, self.value, other) catch return null;
                return .{ .value = o };
            },
            Amount => {
                const o = math.sub(u64, self.value, other.value) catch return null;
                return .{ .value = o };
            },
            else => {
                @compileError("Expected u64 or Amount");
            },
        }
    }

    /// Checked multiplication.
    /// Returns [None] if overflow occurred.
    pub fn checkedMul(self: Amount, scalar: anytype) ?Amount {
        switch (@TypeOf(scalar)) {
            u64 => {
                const o = math.mul(u64, self.value, scalar) catch return null;
                return .{ .value = o };
            },
            Amount => {
                const o = math.mul(u64, self.value, scalar.value) catch return null;
                return .{ .value = o };
            },
            else => {
                @compileError("Expected u64 or Amount");
            },
        }
    }

    /// Checked integer division.
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made.
    /// Returns [None] if overflow occurred.
    pub fn checkedDiv(self: Amount, scalar: anytype) ?Amount {
        switch (@TypeOf(scalar)) {
            u64 => {
                return if (scalar == 0) null else Amount{ .value = math.divFloor(u64, self.value, scalar) catch return null };
            },
            Amount => {
                return if (scalar.value == 0) null else Amount{ .value = math.divFloor(u64, self.value, scalar.value) catch return null };
            },
            else => {
                @compileError("Expected u64 or Amount");
            },
        }
    }

    /// Checked remainder.
    /// Returns [None] if overflow occurred.
    pub fn checkedRem(self: Amount, scalar: anytype) ?Amount {
        switch (@TypeOf(scalar)) {
            u64 => {
                return if (scalar == 0) null else Amount{ .value = math.rem(u64, self.value, scalar) catch return null };
            },
            Amount => {
                return if (scalar.value == 0) null else Amount{ .value = math.rem(u64, self.value, scalar.value) catch return null };
            },
            else => {
                @compileError("Expected u64 or Amount");
            },
        }
    }

    // Some arithmetic that fits in `std::ops` traits.
    pub fn add(self: Amount, other: anytype) ParseAmountError!Amount {
        return self.checkedAdd(other) orelse ParseAmountError.Overflow;
    }

    pub fn addAssign(self: *Amount, other: anytype) ParseAmountError!void {
        self.* = try self.add(other);
    }

    pub fn sub(self: Amount, other: anytype) ParseAmountError!Amount {
        return self.checkedSub(other) orelse ParseAmountError.Overflow;
    }

    pub fn subAssign(self: *Amount, other: anytype) ParseAmountError!void {
        self.* = try self.sub(other);
    }

    pub fn rem(self: Amount, scalar: anytype) ParseAmountError!Amount {
        return self.checkedRem(scalar) orelse ParseAmountError.Overflow;
    }

    pub fn remAssign(self: *Amount, scalar: anytype) ParseAmountError!void {
        self.* = try self.rem(scalar);
    }

    pub fn mul(self: Amount, scalar: anytype) ParseAmountError!Amount {
        return self.checkedMul(scalar) orelse ParseAmountError.Overflow;
    }

    pub fn mulAssign(self: *Amount, scalar: anytype) ParseAmountError!void {
        self.* = try self.mul(scalar);
    }

    pub fn div(self: Amount, scalar: anytype) ParseAmountError!Amount {
        return self.checkedDiv(scalar) orelse ParseAmountError.Overflow;
    }

    pub fn divAssign(self: *Amount, scalar: anytype) ParseAmountError!void {
        self.* = try self.div(scalar);
    }

    /// Convert to signed amount
    pub fn toSigned(self: Amount) ParseAmountError!SignedAmount {
        if (self.value > SignedAmount.maxValue().value) {
            return ParseAmountError.TooBig;
        }
        return SignedAmount{ .value = @as(i64, @intCast(self.value)) };
    }

    pub fn toOwner(self: *const Amount) u64 {
        return self.value;
    }
};

/// Signed amount type for Bitcoin amounts that can be negative
pub const SignedAmount = struct {
    value: i64, // satoshis

    // Constants
    pub const ZERO = SignedAmount{ .value = 0 };
    pub const ONE_SAT = SignedAmount{ .value = 1 };
    pub const ONE_BTC = SignedAmount{ .value = 100_000_000 };

    /// Create an [SignedAmount] with satoshi precision and the given number of satoshis.
    pub fn fromSat(satoshi: i64) SignedAmount {
        return .{ .value = satoshi };
    }
    /// Get the number of satoshis in this [SignedAmount].
    pub fn asSat(self: SignedAmount) i64 {
        return self.value;
    }

    /// The maximum value of an [SignedAmount].
    pub fn maxValue() SignedAmount {
        return .{ .value = math.maxInt(i64) };
    }

    /// The minimum value of an [SignedAmount].
    pub fn minValue() SignedAmount {
        return .{ .value = math.minInt(i64) };
    }

    /// Convert from a value expressing bitcoins to an [SignedAmount].
    pub fn fromBtc(btc: f64) !SignedAmount {
        return fromFloatIn(btc, .bitcoin);
    }

    /// Convert this [SignedAmount] in floating-point notation with a given
    /// denomination.
    /// Can return error if the amount is too big, too precise or negative.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn fromFloatIn(value: f64, denom: Denomination) ParseAmountError!SignedAmount {
        var buf: [32]u8 = undefined;
        const str = std.fmt.bufPrint(&buf, "{d}", .{value}) catch unreachable;
        std.debug.print("str: {s}\n", .{str});
        const sig = try SignedAmount.fromStrIn(str, denom);
        return sig;
    }

    pub fn fromStrIn(str: []const u8, denom: Denomination) ParseAmountError!SignedAmount {
        const result = try parseSignedToSatoshi(str, denom);
        const negative: bool = result[0];
        const satoshi: u64 = result[1];
        if (satoshi > math.maxInt(i64)) return ParseAmountError.TooBig;
        const value = @as(i64, @intCast(satoshi));
        if (negative) return SignedAmount{ .value = -value };
        return SignedAmount{ .value = value };
    }

    /// Parses amounts with denomination suffix like they are produced with
    /// [to_string_with_denomination] or with [fmt::Display].
    /// If you want to parse only the amount without the denomination,
    /// use [from_str_in].
    pub fn fromStrWithDenomination(str: []const u8) ParseAmountError!SignedAmount {
        const split = std.mem.splitSequence(u8, str, ' ');
        const amtStr = split.next() orelse return ParseAmountError.InvalidFormat;
        const denomStr = split.next() orelse return ParseAmountError.InvalidFormat;
        const denom = try Denomination.fromString(denomStr);
        return fromStrIn(amtStr, denom);
    }

    /// Convert to float in given denomination
    pub fn toFloatIn(self: SignedAmount, denom: Denomination) f64 {
        const precision = @as(f64, @floatFromInt(denom.precision()));
        return @as(f64, @floatFromInt(self.value)) * std.math.pow(f64, 10, precision);
    }

    /// Convert to unsigned amount
    pub fn toUnsigned(self: SignedAmount) ParseAmountError!Amount {
        if (self.value < 0) return ParseAmountError.Negative;
        return Amount{ .value = @as(u64, @intCast(self.value)) };
    }

    ///////////////////////////////Operators///////////////////////////////

    pub fn checkedAdd(self: SignedAmount, other: anytype) ?SignedAmount {
        switch (@TypeOf(other)) {
            i64 => {
                const o = math.add(i64, self.value, other) catch return null;
                return .{ .value = o };
            },
            SignedAmount => {
                const o = math.add(i64, self.value, other.value) catch return null;
                return .{ .value = o };
            },
            else => {
                @compileError("Expected i64 or SignedAmount");
            },
        }
    }

    /// Checked addition.
    /// Returns [None] if overflow occurred.
    pub fn add(self: SignedAmount, other: anytype) ParseAmountError!SignedAmount {
        return self.checkedAdd(other) orelse ParseAmountError.Overflow;
    }

    /// Add assign.
    pub fn addAssign(self: *SignedAmount, other: anytype) ParseAmountError!void {
        self.* = try self.add(other);
    }

    /// Checked subtraction.
    /// Returns [None] if overflow occurred.
    pub fn checkedSub(self: SignedAmount, other: anytype) ?SignedAmount {
        switch (@TypeOf(other)) {
            i64 => {
                const o = math.sub(i64, self.value, other) catch return null;
                return .{ .value = o };
            },
            SignedAmount => {
                const o = math.sub(i64, self.value, other.value) catch return null;
                return .{ .value = o };
            },
            else => {
                @compileError("Expected i64 or SignedAmount");
            },
        }
    }

    /// Subtraction.
    pub fn sub(self: SignedAmount, other: anytype) ParseAmountError!SignedAmount {
        return self.checkedSub(other) orelse ParseAmountError.Overflow;
    }

    /// Subtraction assign.
    pub fn subAssign(self: *SignedAmount, other: anytype) ParseAmountError!void {
        self.* = try self.sub(other);
    }

    /// Checked multiplication.
    /// Returns [None] if overflow occurred.
    pub fn checkedMul(self: SignedAmount, scalar: anytype) ?SignedAmount {
        switch (@TypeOf(scalar)) {
            i64 => {
                const o = math.mul(i64, self.value, scalar) catch return null;
                return .{ .value = o };
            },
            SignedAmount => {
                const o = math.mul(i64, self.value, scalar.value) catch return null;
                return .{ .value = o };
            },
            else => {
                @compileError("Expected i64 or SignedAmount");
            },
        }
    }

    /// Multiplication.
    pub fn mul(self: SignedAmount, scalar: anytype) ParseAmountError!SignedAmount {
        return self.checkedMul(scalar) orelse ParseAmountError.Overflow;
    }

    /// Multiplication assign.
    pub fn mulAssign(self: *SignedAmount, scalar: anytype) ParseAmountError!void {
        self.* = try self.mul(scalar);
    }

    /// Checked division.
    /// Returns [None] if overflow occurred.
    pub fn checkedDiv(self: SignedAmount, scalar: anytype) ?SignedAmount {
        switch (@TypeOf(scalar)) {
            i64 => {
                return if (scalar == 0) null else SignedAmount{ .value = math.divFloor(i64, self.value, scalar) catch return null };
            },
            SignedAmount => {
                return if (scalar.value == 0) null else SignedAmount{ .value = math.divFloor(i64, self.value, scalar.value) catch return null };
            },
            else => {
                @compileError("Expected i64 or SignedAmount");
            },
        }
    }

    /// Division.
    pub fn div(self: SignedAmount, scalar: anytype) ParseAmountError!SignedAmount {
        return self.checkedDiv(scalar) orelse ParseAmountError.Overflow;
    }

    /// Division assign.
    pub fn divAssign(self: *SignedAmount, scalar: anytype) ParseAmountError!void {
        self.* = try self.div(scalar);
    }

    /// Checked remainder.
    /// Returns [None] if overflow occurred.
    pub fn checkedRem(self: SignedAmount, scalar: anytype) ?SignedAmount {
        switch (@TypeOf(scalar)) {
            i64 => {
                return if (scalar == 0) null else SignedAmount{ .value = math.rem(i64, self.value, scalar) catch return null };
            },
            SignedAmount => {
                return if (scalar.value == 0) null else SignedAmount{ .value = math.rem(i64, self.value, scalar.value) catch return null };
            },
            else => {
                @compileError("Expected i64 or SignedAmount");
            },
        }
    }

    /// Remainder.
    pub fn rem(self: SignedAmount, scalar: anytype) ParseAmountError!SignedAmount {
        return self.checkedRem(scalar) orelse ParseAmountError.Overflow;
    }

    /// Remainder assign.
    pub fn remAssign(self: *SignedAmount, scalar: anytype) ParseAmountError!void {
        self.* = try self.rem(scalar);
    }

    /// Subtraction that doesn't allow negative [SignedAmount]s.
    /// Returns [None] if either [self], [rhs] or the result is strictly negative.
    pub fn positiveSub(self: SignedAmount, rhs: SignedAmount) ?SignedAmount {
        if (self.value < 0 or rhs.value < 0 or self.value - rhs.value < 0) return null;
        return self.checkedSub(rhs);
    }

    // Some arithmetic that doesn't fit in `std::ops` traits.

    /// Get the absolute value of this [SignedAmount].
    pub fn abs(self: *const SignedAmount) SignedAmount {
        return .{ .value = @abs(self.value) };
    }

    /// Returns a number representing sign of this [SignedAmount].
    ///
    /// - `0` if the amount is zero
    /// - `1` if the amount is positive
    /// - `-1` if the amount is negative
    pub fn signum(self: *const SignedAmount) i64 {
        return @divFloor(self.value, @abs(self.value));
    }

    /// Returns `true` if this [SignedAmount] is positive and `false` if
    /// this [SignedAmount] is zero or negative.
    pub fn isPositive(self: *const SignedAmount) bool {
        return self.value > 0;
    }

    /// Returns `true` if this [SignedAmount] is negative and `false` if
    /// this [SignedAmount] is zero or positive.
    pub fn isNegative(self: *const SignedAmount) bool {
        return self.value < 0;
    }

    /// Returns `true` if this [SignedAmount] is zero.
    pub fn isZero(self: *const SignedAmount) bool {
        return self.value == 0;
    }
};

test "isTooPrecise" {
    try std.testing.expect(isTooPrecise("123.456", 2));
    try std.testing.expect(isTooPrecise("123.456", 3));
    try std.testing.expect(isTooPrecise("123", 2));
    try std.testing.expect(isTooPrecise("123.000001", 5));
}
