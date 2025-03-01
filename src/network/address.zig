const std = @import("std");

/// A network address
pub const Address = struct {
    /// The IP address of the peer
    ip: std.net.Address,
};
