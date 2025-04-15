const std = @import("std");
const blockdata = @import("../blockdata/lib.zig");
const util = @import("../util/lib.zig");
const b58 = util.b58;
const bech32 = util.bech32;
const hashTypes = @import("../hashtypes/lib.zig");
const Script = blockdata.script.Script;
const Builder = blockdata.script.Builder;
const opcode = blockdata.opcode;
const All = opcode.All;
const all = opcode.all;
const PublicKey = util.key.PublicKey;

/// network type enum
pub const Network = enum {
    bitcoin,
    testnet,
    regtest,
};

/// address type enum
pub const AddressType = enum {
    P2pkh, // pay-to-pubkey-hash
    P2sh, // pay-to-script-hash
    P2wpkh, // pay-to-witness-pubkey-hash
    P2wsh, // pay-to-witness-script-hash,

    pub fn toString(self: AddressType) []const u8 {
        return switch (self) {
            .P2pkh => "p2pkh",
            .P2sh => "p2sh",
            .P2wpkh => "p2wpkh",
            .P2wsh => "p2wsh",
        };
    }
};

/// Error type
pub const Error = error{
    BadByte,
    BadChecksum,
    InvalidLength,
    InvalidVersion,
    TooShort,
    EmptyBech32Payload,
    InvalidWitnessVersion,
    InvalidWitnessProgramLength,
    InvalidSegwitV0ProgramLength,
    UncompressedPubkey,
    InvalidScript,
} || b58.Error || bech32.Error;

/// Address payload type
pub const Payload = union(enum) {
    PubkeyHash: [20]u8, // The hash of the public key
    ScriptHash: [20]u8, // The hash of the script
    WitnessProgram: struct {
        version: u5,
        program: []u8,
    },
    /// Get a [Payload] from an output script (scriptPubkey).
    pub fn fromScript(allocator: std.mem.Allocator, script: *const Script) ?Payload {
        if (script.isP2pkh()) {
            var hash = allocator.alloc(u8, 20) catch unreachable;
            hashTypes.PubkeyHash.hash(script.asBytes()[3..23], hash[0..20]);
            return Payload{ .PubkeyHash = hash[0..20].* };
        }
        if (script.isP2sh()) {
            var hash = allocator.alloc(u8, 20) catch unreachable;
            hashTypes.ScriptHash.hash(script.asBytes()[2..22], hash[0..20]);
            return Payload{ .ScriptHash = hash[0..20].* };
        }
        if (script.isWitnessProgram()) {
            // We can unwrap the u5 check and assume script length
            // because [Script::is_witness_program] makes sure of this.
            var verop = script.asBytes()[0];
            if (verop > 0x50) {
                verop -= 0x50;
            }
            const version = @as(u5, @intCast(verop));
            // Since we passed the [is_witness_program] check,
            // the first byte is either 0x00 or 0x50 + version.
            return Payload{ .WitnessProgram = .{
                .version = version,
                .program = allocator.dupe(u8, script.asBytes()[2..]) catch unreachable,
            } };
        }
        return null;
        // var hash = allocator.alloc(u8, 20) catch unreachable;
        // hashTypes.ScriptHash.hash(script.asBytes(), hash[0..20]);
        // return Payload{ .ScriptHash = hash[0..20].* };
    }
    /// Generates a script pubkey spending to this [Payload].
    pub fn scriptPubKey(
        self: *const Payload,
        allocator: std.mem.Allocator,
    ) Script {
        switch (self.*) {
            .PubkeyHash => |hash| {
                var builder = Builder.init(allocator);
                _ = builder.pushOpcode(all.OP_DUP)
                    .pushOpcode(all.OP_HASH160)
                    .pushSlice(&hash)
                    .pushOpcode(all.OP_EQUALVERIFY)
                    .pushOpcode(all.OP_CHECKSIG);
                return builder.build();
            },
            .ScriptHash => |hash| {
                var builder = Builder.init(allocator);
                _ = builder.pushOpcode(all.OP_HASH160)
                    .pushSlice(&hash)
                    .pushOpcode(all.OP_EQUAL);
                return builder.build();
            },
            .WitnessProgram => |wp| {
                const ver: u8 = if (wp.version > 0) @as(u8, wp.version) + 0x50 else 0;
                var builder = Builder.init(allocator);
                _ = builder.pushOpcode(opcode.All.from_u8(ver))
                    .pushSlice(wp.program);
                return builder.build();
            },
        }
    }

    pub fn deinit(self: Payload, allocator: std.mem.Allocator) void {
        switch (self) {
            .PubkeyHash => |hash| {
                allocator.free(hash);
            },
            .ScriptHash => |hash| {
                allocator.free(hash);
            },
            .WitnessProgram => |wp| {
                allocator.free(wp.program);
            },
        }
    }
};

/// Address type
pub const Address = struct {
    payload: Payload,
    network: Network,
    allocator: std.mem.Allocator,

    pub fn deinit(self: Address) void {
        self.payload.deinit(self.allocator);
    }

    pub fn toJson(self: Address, allocator: std.mem.Allocator) ![]u8 {
        return std.json.stringifyAlloc(allocator, .{
            .payload = self.payload,
            .network = self.network,
        }, .{}) catch unreachable;
    }

    /// Creates a pay to (compressed) public key hash address from a public key
    /// This is the preferred non-witness type address
    pub fn p2pkh(allocator: std.mem.Allocator, pk: *const PublicKey, network: Network) !Address {
        var hash = allocator.alloc(u8, 20) catch unreachable;
        hashTypes.PubkeyHash.hash(try pk.asBytes(), hash[0..20]);
        return Address{
            .payload = .{ .PubkeyHash = hash[0..20].* },
            .network = network,
            .allocator = allocator,
        };
    }

    /// Creates a pay to script hash P2SH address from a script
    /// This address type was introduced with BIP16 and is the popular type to implement multi-sig these days.
    pub fn p2sh(allocator: std.mem.Allocator, script: *const Script, network: Network) !Address {
        var hash = allocator.alloc(u8, 20) catch unreachable;
        hashTypes.ScriptHash.hash(script.asBytes(), hash[0..20]);
        return Address{
            .payload = .{ .ScriptHash = hash[0..20].* },
            .network = network,
            .allocator = allocator,
        };
    }

    /// Create a witness pay to public key address from a public key
    /// This is the native segwit address type for an output redeemable with a single signature
    ///
    /// Will only return an Error when an uncompressed public key is provided.
    pub fn p2wpkh(allocator: std.mem.Allocator, pk: *const PublicKey, network: Network) !Address {
        if (!pk.compressed) {
            return Error.UncompressedPubkey;
        }
        var hash = allocator.alloc(u8, 20) catch unreachable;
        hashTypes.WPubkeyHash.hash(try pk.asBytes(), hash[0..20]);
        return Address{
            .network = network,
            .payload = .{ .WitnessProgram = .{
                .version = 0,
                .program = hash,
            } },
            .allocator = allocator,
        };
    }

    /// Create a pay to script address that embeds a witness pay to public key
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients
    ///
    /// Will only return an Error when an uncompressed public key is provided.
    pub fn p2shwpkh(allocator: std.mem.Allocator, pk: *const PublicKey, network: Network) !Address {
        if (!pk.compressed) {
            return Error.UncompressedPubkey;
        }

        var hash = allocator.alloc(u8, 20) catch unreachable;
        errdefer allocator.free(hash);
        hashTypes.WPubkeyHash.hash(try pk.asBytes(), hash[0..20]);
        var builder = Builder.init(allocator);
        defer builder.deinit();
        var script = builder.pushInt(0).pushSlice(hash[0..]).build();
        defer script.deinit();
        hashTypes.ScriptHash.hash(script.asBytes(), hash[0..20]);
        return Address{
            .network = network,
            .payload = .{ .ScriptHash = hash[0..20].* },
            .allocator = allocator,
        };
    }

    /// Create a witness pay to script hash address
    pub fn p2wsh(allocator: std.mem.Allocator, script: *const Script, network: Network) Address {
        var hash = allocator.alloc(u8, 32) catch unreachable;
        hashTypes.WScriptHash.hash(script.asBytes(), hash[0..32]);
        return Address{
            .network = network,
            .payload = .{ .WitnessProgram = .{
                .version = 0,
                .program = hash,
            } },
            .allocator = allocator,
        };
    }

    /// Create a pay to script address that embeds a witness pay to script hash address
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients
    pub fn p2shwsh(allocator: std.mem.Allocator, script: *const Script, network: Network) Address {
        var hash: [32]u8 = undefined;
        errdefer allocator.free(hash);
        hashTypes.WScriptHash.hash(script.asBytes(), hash[0..32]);
        var builder = Builder.init(allocator);
        defer builder.deinit();
        // 0 is the version for witness program
        var ws = builder.pushInt(0).pushSlice(hash[0..32]).build();
        defer ws.deinit();
        hashTypes.ScriptHash.hash(ws.asBytes(), hash[0..20]);
        const hash20 = allocator.alloc(u8, 20) catch unreachable;
        defer allocator.free(hash20);
        @memcpy(hash20, hash[0..20]);
        return .{
            .network = network,
            .payload = .{
                .ScriptHash = hash20[0..20].*,
            },
            .allocator = allocator,
        };
    }

    /// Get the address type of the address.
    /// None if unknown or non-standard.
    pub fn addressType(self: *const Address) ?AddressType {
        return switch (self.payload) {
            .PubkeyHash => .P2pkh,
            .ScriptHash => .P2sh,
            .WitnessProgram => |wp| switch (wp.version) {
                0 => switch (wp.program.len) {
                    20 => .P2wpkh,
                    32 => .P2wsh,
                    else => null,
                },
                else => null,
            },
        };
    }

    /// Check whether or not the address is following Bitcoin
    /// standardness rules.
    ///
    /// Segwit addresses with unassigned witness versions or non-standard
    /// program sizes are considered non-standard.
    pub fn isStandard(self: *const Address) bool {
        return self.addressType() != null;
    }

    /// Get an [Address] from an output script (scriptPubkey).
    pub fn fromScript(allocator: std.mem.Allocator, script: *const Script, network: Network) Error!Address {
        if (Payload.fromScript(allocator, script)) |payload| {
            return .{
                .network = network,
                .payload = payload,
                .allocator = allocator,
            };
        }
        return Error.InvalidScript;
    }

    /// Generates a script pubkey spending to this address
    pub fn scriptPubKey(self: *const Address, allocator: std.mem.Allocator) Script {
        return self.payload.scriptPubKey(allocator);
    }

    /// Conver address to slice.
    pub fn toString(self: *const Address, allocator: std.mem.Allocator) ![]u8 {
        return switch (self.*.payload) {
            .PubkeyHash => |hash| blk: {
                var data: [21]u8 = undefined;
                data[0] = switch (self.network) {
                    .bitcoin => 0,
                    .testnet, .regtest => 111,
                };
                @memcpy(data[1..], &hash);
                break :blk try b58.checkEncodeSliceToFmt(allocator, &data);
            },
            .ScriptHash => |hash| blk: {
                var data: [21]u8 = undefined;
                data[0] = switch (self.network) {
                    .bitcoin => 5,
                    .testnet, .regtest => 196,
                };
                @memcpy(data[1..], &hash);
                break :blk try b58.checkEncodeSliceToFmt(allocator, &data);
            },
            .WitnessProgram => |wp| blk: {
                const hrp = switch (self.network) {
                    .bitcoin => "bc",
                    .testnet => "tb",
                    .regtest => "bcrt",
                };
                // TODO Optimize the code by using a more efficient memory allocation
                var dest: [100]u8 = undefined;
                const result = bech32.standard.Encoder.encode(&dest, hrp, wp.program, wp.version, .bech32);
                std.testing.expect(result.len <= dest.len) catch unreachable;
                break :blk allocator.dupe(u8, result) catch unreachable;
            },
        };
    }

    /// Get an [Address] from a string.
    /// The string can be a base58 encoded address or a bech32 encoded address.
    pub fn fromString(allocator: std.mem.Allocator, s: []const u8) Error!Address {
        // try bech32
        const bech32NetWork: ?Network = blk: {
            const prefix = findBech32Prefix(s);
            if (std.mem.eql(u8, prefix, "bc") or std.mem.eql(u8, prefix, "BC")) {
                break :blk Network.bitcoin;
            } else if (std.mem.eql(u8, prefix, "tb") or std.mem.eql(u8, prefix, "TB")) {
                break :blk Network.testnet;
            } else if (std.mem.eql(u8, prefix, "bcrt") or std.mem.eql(u8, prefix, "BCRT")) {
                break :blk Network.regtest;
            } else {
                break :blk null;
            }
        };
        if (bech32NetWork) |_network| {
            // decode as bech32
            var dest: [100]u8 = undefined;
            const result = try bech32.standard.Decoder.decode(&dest, s);
            if (result.data.len == 0) {
                return Error.EmptyBech32Payload;
            }
            // Get the script version and program (converted from 5-bit to 8-bit)
            const program = result.data;
            const version = result.version;
            // Generic segwit checks.
            if (version > 16) {
                return Error.InvalidWitnessVersion;
            }
            if (program.len < 2 or program.len > 40) {
                return Error.InvalidWitnessProgramLength;
            }

            // Specific segwit v0 check.
            if (version == 0 and (program.len != 20 and program.len != 32)) {
                return Error.InvalidSegwitV0ProgramLength;
            }

            return Address{
                .network = _network,
                .payload = .{
                    .WitnessProgram = .{
                        .version = version,
                        .program = allocator.dupe(u8, program) catch unreachable,
                    },
                },
                .allocator = allocator,
            };
        }

        // other decode format
        // Base58
        if (s.len > 50) {
            return Error.InvalidLength;
        }
        var payload = try b58.fromCheck(allocator, s);
        if (payload.len != 21) {
            return Error.InvalidLength;
        }
        var _network: Network = undefined;
        var _payload = allocator.alloc(u8, 20) catch unreachable;
        errdefer allocator.free(_payload);
        switch (payload[0]) {
            0 => {
                _network = .bitcoin;
                hashTypes.PubkeyHash.hash(payload[1..], _payload[0..20]);
            },
            5 => {
                _network = .bitcoin;
                hashTypes.ScriptHash.hash(payload[1..], _payload[0..20]);
            },
            111 => {
                _network = .testnet;
                hashTypes.PubkeyHash.hash(payload[1..], _payload[0..20]);
            },
            196 => {
                _network = .testnet;
                hashTypes.ScriptHash.hash(payload[1..], _payload[0..20]);
            },
            else => {
                return Error.InvalidVersion;
            },
        }

        return Address{
            .network = _network,
            .payload = .{ .PubkeyHash = _payload[0..20].* },
            .allocator = allocator,
        };
    }
};

/// Extract the bech32 prefix.
/// Returns the same slice when no prefix is found.
fn findBech32Prefix(bech32Str: []const u8) []const u8 {
    // Split at the last occurrence of the separator character '1'.
    if (std.mem.indexOf(u8, bech32Str, "1")) |index| {
        return bech32Str[0..index];
    } else {
        return bech32Str;
    }
}
