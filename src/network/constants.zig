const std = @import("std");

/// Version of the protocol as appearing in network message headers
pub const PROTOCOL_VERSION: u32 = 70001;

/// The cryptocurrency network to act on
pub const Network = enum {
    /// Classic Bitcoin
    bitcoin,
    /// Bitcoin's testnet
    testnet,
    /// Bitcoin's regtest
    regtest,

    /// Creates a Network from the magic bytes.
    pub fn fromMagic(_magic: u32) ?Network {
        return switch (_magic) {
            0xD9B4BEF9 => .bitcoin,
            0x0709110B => .testnet,
            0xDAB5BFFA => .regtest,
            else => null,
        };
    }

    /// Return the network magic bytes, which should be encoded little-endian
    /// at the start of every message
    pub fn magic(self: Network) u32 {
        return switch (self) {
            .bitcoin => 0xD9B4BEF9,
            .testnet => 0x0709110B,
            .regtest => 0xDAB5BFFA,
        };
    }

    pub fn toString(self: Network) []const u8 {
        return switch (self) {
            .bitcoin => "bitcoin",
            .testnet => "testnet",
            .regtest => "regtest",
        };
    }
};

/// Flags to indicate which network services a node supports
pub const ServiceFlags = struct {
    flags: u64,

    const Self = @This();

    pub const NONE: Self = Self{ .flags = 0 };
    pub const NETWORK: Self = Self{ .flags = 1 << 0 };
    pub const GETUTXO: Self = Self{ .flags = 1 << 1 };
    pub const BLOOM: Self = Self{ .flags = 1 << 2 };
    pub const WITNESS: Self = Self{ .flags = 1 << 3 };
    pub const COMPACT_FILTERS: Self = Self{ .flags = 1 << 6 };
    pub const NETWORK_LIMITED: Self = Self{ .flags = 1 << 10 };

    /// Add ServiceFlags together
    pub fn add(self: *Self, other: Self) Self {
        self.flags |= other.flags;
        return self.*;
    }

    /// Remove ServiceFlags from this
    pub fn remove(self: *Self, other: Self) Self {
        self.flags ^= other.flags;
        return self.*;
    }

    /// Check whether ServiceFlags are included in this one
    pub fn has(self: Self, flags: Self) bool {
        return (self.flags | flags.flags) == self.flags;
    }

    /// Get the integer representation of this ServiceFlags
    pub fn asU64(self: Self) u64 {
        return self.flags;
    }

    pub fn format(
        self: Self,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        if (self.flags == 0) {
            try writer.writeAll("ServiceFlags(NONE)");
            return;
        }

        try writer.writeAll("ServiceFlags(");
        var first = true;
        var flags = self;

        inline for (.{
            .{ "NETWORK", NETWORK },
            .{ "GETUTXO", GETUTXO },
            .{ "BLOOM", BLOOM },
            .{ "WITNESS", WITNESS },
            .{ "COMPACT_FILTERS", COMPACT_FILTERS },
            .{ "NETWORK_LIMITED", NETWORK_LIMITED },
        }) |flag| {
            if (flags.has(flag[1])) {
                if (!first) {
                    try writer.writeAll("|");
                }
                first = false;
                try writer.writeAll(flag[0]);
                flags.remove(flag[1]);
            }
        }

        if (flags.flags != 0) {
            if (!first) {
                try writer.writeAll("|");
            }
            try std.fmt.format(writer, "0x{x}", .{flags.flags});
        }

        try writer.writeAll(")");
    }
};

test "network magic" {
    try std.testing.expectEqual(Network.bitcoin.magic(), 0xD9B4BEF9);
    try std.testing.expectEqual(Network.testnet.magic(), 0x0709110B);
    try std.testing.expectEqual(Network.regtest.magic(), 0xDAB5BFFA);

    try std.testing.expectEqual(Network.fromMagic(0xD9B4BEF9).?, .bitcoin);
    try std.testing.expectEqual(Network.fromMagic(0x0709110B).?, .testnet);
    try std.testing.expectEqual(Network.fromMagic(0xDAB5BFFA).?, .regtest);
    try std.testing.expect(Network.fromMagic(0xFFFFFFFF) == null);
}

test "service flags" {
    var flags = ServiceFlags.NONE;
    try std.testing.expect(!flags.has(ServiceFlags.NETWORK));
    try std.testing.expect(!flags.has(ServiceFlags.GETUTXO));
    try std.testing.expect(!flags.has(ServiceFlags.BLOOM));
    try std.testing.expect(!flags.has(ServiceFlags.WITNESS));
    try std.testing.expect(!flags.has(ServiceFlags.COMPACT_FILTERS));
    try std.testing.expect(!flags.has(ServiceFlags.NETWORK_LIMITED));

    flags = flags.add(ServiceFlags.WITNESS);
    try std.testing.expectEqual(flags, ServiceFlags.WITNESS);

    var flags2 = flags.add(ServiceFlags.GETUTXO);
    try std.testing.expect(flags2.has(ServiceFlags.WITNESS));
    try std.testing.expect(flags2.has(ServiceFlags.GETUTXO));

    flags2 = flags2.remove(ServiceFlags.WITNESS);
    try std.testing.expectEqual(flags2, ServiceFlags.GETUTXO);

    flags2 = flags2.add(ServiceFlags.COMPACT_FILTERS);
    flags2 = flags2.remove(ServiceFlags.GETUTXO);
    try std.testing.expectEqual(flags2, ServiceFlags.COMPACT_FILTERS);
}
