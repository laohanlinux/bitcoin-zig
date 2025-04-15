//! # Raw PSBT Key-Value Pairs
//!
//! Raw PSBT key-value pairs as defined at
//! https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki.

const consensus = @import("../../consensus/lib.zig");
const encode = consensus.encode;

const std = @import("std");
/// A PSBT key in its raw byte form.
pub const Key = struct {
    /// The type of this PSBT key.
    type_value: u8,
    /// The key itself in raw byte form.
    key: []const u8,
    allocator: std.mem.Allocator,

    /// Initialize a new PSBT key.
    pub fn init(allocator: std.mem.Allocator, type_value: u8, key: []const u8) @This() {
        return .{ .type_value = type_value, .key = key, .allocator = allocator };
    }

    /// Deinitialize a PSBT key.
    pub fn deinit(self: @This()) void {
        self.allocator.free(self.key);
    }

    /// Convert the PSBT key to a string.
    pub fn toString(self: @This(), allocator: std.mem.Allocator) ![]const u8 {
        const keyHex = try std.fmt.fmtSliceHexLower(self.key);
        return try std.fmt.allocPrint(allocator, "type: {#:0x}{s}", .{ self.type_value, keyHex });
    }

    /// Encode and decode the PSBT key.
    pub fn consensusEncDec() encode.EncDec(@This()) {
        return .{};
    }
};

/// A PSBT key-value pair in its raw byte form.
pub const Pair = struct {
    /// The key of this key-value pair.
    key: Key,
    /// The value of this key-value pair in raw byte form.
    value: []const u8,

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, key: Key, value: []const u8) @This() {
        return .{ .key = key, .value = value, .allocator = allocator };
    }

    pub fn deinit(self: @This()) void {
        self.key.deinit();
        self.allocator.free(self.value);
    }

    pub fn toString(self: @This(), allocator: std.mem.Allocator) ![]const u8 {
        const keyHex = try std.fmt.fmtSliceHexLower(self.key);
        return try std.fmt.allocPrint(allocator, "type: {#:0x}{s}", .{ self.key.type_value, keyHex });
    }

    pub fn consensusEncDec() encode.EncDec(@This()) {
        return .{};
    }
};
