const std = @import("std");

/// The `version` message
pub const VersionMessage = struct {
    /// The P2P network protocol version
    version: u32,
    /// A bitmask describing the services supported by this node
    services: ServiceFlag,
    /// The time at which the `version` message was sent
    timestamp: i64,
    /// The network address of the peer receiving the message
    receiver: Address,
    /// The network address of the peer sending the message
    sender: Address,
    /// A random nonce used to detect loops in the network
    nonce: u64,
    /// A string describing the peer's software
    user_agent: []const u8,
    /// The height of the maximum-work blockchain that the peer is aware of
    start_height: i32,
    /// Whether the receiving peer should relay messages to the sender; used
    /// if the sender is bandwidth-limited and would like to support bloom
    /// filtering. Defaults to false.
    relay: bool,

    /// Constructs a new `version` message with `relay` set to false
    pub fn new(
        services: ServiceFlags,
        timestamp: i64,
        receiver: Address,
        sender: Address,
        nonce: u64,
        user_agent: []const u8,
        start_height: i32,
    ) VersionMessage {
        return VersionMessage{
            .version = constants.PROTOCOL_VERSION,
            .services = services,
            .timestamp = timestamp,
            .receiver = receiver,
            .sender = sender,
            .nonce = nonce,
            .user_agent = user_agent,
            .start_height = start_height,
            .relay = false,
        };
    }
};

/// A bitmask describing the services supported by a node
pub const ServiceFlag = packed struct {
    /// The node is a full block chain node
    network: bool = false,
    /// The node is a compact block chain node
    compact_block: bool = false,
};
