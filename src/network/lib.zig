const std = @import("std");
pub const constants = @import("constants.zig");
pub const address = @import("address.zig");

// Network error
pub const Error = error{
    /// Socket mutex was poisoned
    SocketMutexPoisoned,
    /// Not connected to peer
    SocketNotConnectedToPeer,
} || std.os.SocketError || std.io.Error;

/// Convert an error to a string.
pub fn errorToString(err: Error) []const u8 {
    return switch (err) {
        Error.SocketMutexPoisoned => "socket mutex was poisoned",
        Error.SocketNotConnectedToPeer => "not connected to peer",
        else => |e| switch (@as(anyerror, e)) {
            else => @errorName(e),
        },
    };
}

/// Format an error to a writer.
pub fn formatError(err: Error, writer: anytype) !void {
    try writer.writeAll(errorToString(err));
}
