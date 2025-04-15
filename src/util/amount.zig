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
    milli_bitcoin,
    /// uBTC
    micro_bitcoin,
    /// bits
    bit,
    /// satoshi
    satoshi,
    /// msat
    milli_satoshi,

    /// Get the number of decimal places relative to a satoshi
    pub fn precision(self: Denomination) i32 {
        return switch (self) {
            .bitcoin => -8,
            .milli_bitcoin => -5,
            .micro_bitcoin => -2,
            .bit => -2,
            .satoshi => 0,
            .milli_satoshi => 3,
        };
    }

    /// Convert denomination to string representation
    pub inline fn toString(self: Denomination) []const u8 {
        return switch (self) {
            .bitcoin => "BTC",
            .milli_bitcoin => "mBTC",
            .micro_bitcoin => "uBTC",
            .bit => "bits",
            .satoshi => "satoshi",
            .milli_satoshi => "msat",
        };
    }

    /// Parse denomination from string
    pub inline fn fromString(str: []const u8) !Denomination {
        if (std.mem.eql(u8, str, "BTC")) return .bitcoin;
        if (std.mem.eql(u8, str, "mBTC")) return .milli_bitcoin;
        if (std.mem.eql(u8, str, "uBTC")) return .micro_bitcoin;
        if (std.mem.eql(u8, str, "bits")) return .bit;
        if (std.mem.eql(u8, str, "satoshi") or std.mem.eql(u8, str, "sat")) return .satoshi;
        if (std.mem.eql(u8, str, "msat")) return .milli_satoshi;
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
    Overflow,
};

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
fn isTooPrecise(str: []const u8, precision: usize) bool {
    if (std.mem.indexOf(u8, str, ".") != null) return true;
    if (precision >= str.len) return true;
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
    const valueStr = if (isNegative) str[1..] else str;

    if (valueStr.len == 0) return ParseAmountError.InvalidFormat;

    // Calculate maximum allowed decimals
    const precisionDiff = -denom.precision();
    const maxDecimals = if (precisionDiff < 0) blk: {
        // Less precise denomination
        const lastN = @as(usize, @intCast(-precisionDiff));
        if (isTooPrecise(valueStr, lastN)) return ParseAmountError.TooPrecise;
        break :blk 0;
    } else precisionDiff;

    var decimals: ?usize = null;
    var value: u64 = 0;

    for (valueStr) |c| {
        switch (c) {
            '0'...'9' => {
                // value = 10 * value + digit
                const digit = c - '0';
                value = math.mul(u64, value, 10) catch return ParseAmountError.InputTooLarge;
                value = math.add(u64, value, digit) catch return ParseAmountError.InputTooLarge;

                // Track decimal places
                if (decimals) |d| {
                    if (d >= maxDecimals) return ParseAmountError.TooPrecise;
                    decimals = d + 1;
                }
            },
            '.' => {
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
        value = math.mul(u64, value, 10) catch return ParseAmountError.InputTooLarge;
    }

    return .{ isNegative, value };
}

/// Format satoshi amount in given denomination
fn formatSatoshiIn(
    allocator: std.mem.Allocator,
    satoshi: u64,
    negative: bool,
    denom: Denomination,
) ParseAmountError![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();

    if (negative) {
        try buf.append('-');
    }

    const precision = denom.precision();
    switch (std.math.order(0, precision)) {
        .gt => {
            // Add zeros at end
            const width = @as(usize, @intCast(precision));
            fmt.format(buf.writer(), "{d}{d:0>{}}", .{ satoshi, 0, width }) catch unreachable;
        },
        .lt => {
            // Insert decimal point
            const nbDecimals = @as(usize, @intCast(-precision));
            const str = fmt.allocPrint(allocator, "{d:0>{}}", .{ satoshi, nbDecimals }) catch unreachable;
            defer allocator.free(str);

            if (str.len == nbDecimals) {
                fmt.format(buf.writer(), "0.{s}", .{str}) catch unreachable;
            } else {
                fmt.format(buf.writer(), "{s}.{s}", .{ str[0 .. str.len - nbDecimals], str[str.len - nbDecimals ..] }) catch unreachable;
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
    pub fn asBtc(self: Amount) f64 {
        return self.toFloatIn(.bitcoin);
    }

    /// Parse amount string with denomination
    pub fn fromString(str: []const u8, denom: Denomination) ParseAmountError!Amount {
        const result = try parseSignedToSatoshi(str, denom);
        if (result[0]) return ParseAmountError.Negative;
        if (result[1] > math.maxInt(i64)) return ParseAmountError.TooBig;
        return Amount{ .value = result[1] };
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
    pub fn toFloatIn(self: Amount, denom: Denomination) f64 {
        const precision = @as(f64, @floatCast(denom.precision()));
        return @as(f64, @floatCast(self.value)) * std.math.pow(f64, 10, precision);
    }

    /// Convert from float in given denomination
    pub fn fromFloatIn(value: f64, denom: Denomination) ParseAmountError!Amount {
        if (value < 0.0) return error.Negative;

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
                return if (scalar == 0) null else Amount{ .value = @divFloor(self.value, scalar) };
            },
            Amount => {
                return if (scalar.value == 0) null else Amount{ .value = @divFloor(self.value, scalar.value) };
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
                return if (scalar == 0) null else Amount{ .value = @rem(self.value, scalar) };
            },
            Amount => {
                return if (scalar.value == 0) null else Amount{ .value = @mod(self.value, scalar.value) };
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
        return SignedAmount.fromString(value, denom).toSigned();
    }

    pub fn fromStrIn(str: []const u8, denom: Denomination) ParseAmountError!SignedAmount {
        const result = try parseSignedToSatoshi(str, denom);
        if (result[1] > math.maxInt(i64)) return ParseAmountError.TooBig;
        const value = @as(i64, @intCast(result[1]));
        if (result[0]) return SignedAmount{ .value = -value };
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

    pub fn toFloatIn(self: SignedAmount, denom: Denomination) f64 {
        const precision = @as(f64, @floatCast(denom.precision()));
        return @as(f64, @floatCast(self.value)) * std.math.pow(f64, 10, precision);
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

    pub fn add(self: SignedAmount, other: anytype) ParseAmountError!SignedAmount {
        return self.checkedAdd(other) orelse ParseAmountError.Overflow;
    }

    pub fn addAssign(self: *SignedAmount, other: anytype) ParseAmountError!void {
        self.* = try self.add(other);
    }

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

    pub fn sub(self: SignedAmount, other: anytype) ParseAmountError!SignedAmount {
        return self.checkedSub(other) orelse ParseAmountError.Overflow;
    }

    pub fn subAssign(self: *SignedAmount, other: anytype) ParseAmountError!void {
        self.* = try self.sub(other);
    }

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

    pub fn mul(self: SignedAmount, scalar: anytype) ParseAmountError!SignedAmount {
        return self.checkedMul(scalar) orelse ParseAmountError.Overflow;
    }

    pub fn mulAssign(self: *SignedAmount, scalar: anytype) ParseAmountError!void {
        self.* = try self.mul(scalar);
    }

    pub fn checkedDiv(self: SignedAmount, scalar: anytype) ?SignedAmount {
        switch (@TypeOf(scalar)) {
            i64 => {
                return if (scalar == 0) null else SignedAmount{ .value = @divFloor(self.value, scalar) };
            },
            SignedAmount => {
                return if (scalar.value == 0) null else SignedAmount{ .value = @divFloor(self.value, scalar.value) };
            },
            else => {
                @compileError("Expected i64 or SignedAmount");
            },
        }
    }

    pub fn div(self: SignedAmount, scalar: anytype) ParseAmountError!SignedAmount {
        return self.checkedDiv(scalar) orelse ParseAmountError.Overflow;
    }

    pub fn divAssign(self: *SignedAmount, scalar: anytype) ParseAmountError!void {
        self.* = try self.div(scalar);
    }

    pub fn checkedRem(self: SignedAmount, scalar: anytype) ?SignedAmount {
        switch (@TypeOf(scalar)) {
            i64 => {
                return if (scalar == 0) null else SignedAmount{ .value = @rem(self.value, scalar) };
            },
            SignedAmount => {
                return if (scalar.value == 0) null else SignedAmount{ .value = @rem(self.value, scalar.value) };
            },
            else => {
                @compileError("Expected i64 or SignedAmount");
            },
        }
    }

    pub fn rem(self: SignedAmount, scalar: anytype) ParseAmountError!SignedAmount {
        return self.checkedRem(scalar) orelse ParseAmountError.Overflow;
    }

    pub fn remAssign(self: *SignedAmount, scalar: anytype) ParseAmountError!void {
        self.* = try self.rem(scalar);
    }
};
