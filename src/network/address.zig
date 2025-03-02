const std = @import("std");
const net = std.net;
const mem = std.mem;

pub const Address = struct {
    services: u64,
    address: [8]u16,
    port: u16,

    pub fn new(socket: net.Address, services: u64) Address {
        var addr: [8]u16 = undefined;
        var port: u16 = 0;

        switch (socket) {
            .in => |addr4| {
                addr = ipv4ToIpv6Mapped(addr4.address);
                port = addr4.port;
            },
            .in6 => |addr6| {
                addr = addr6.address;
                port = addr6.port;
            },
            else => unreachable,
        }

        return Address{
            .services = services,
            .address = addr,
            .port = port,
        };
    }

    pub fn socketAddr(self: Address) !net.Address {
        if (self.address[0..3] == ONION) {
            return error.AddrNotAvailable;
        }

        if (isIpv4Mapped(self.address)) {
            return net.Address{ .ipv4 = .{
                .address = ipv6MappedToIpv4(self.address),
                .port = self.port,
            } };
        }

        return net.Address{ .ipv6 = .{
            .address = self.address,
            .port = self.port,
        } };
    }
};

const ONION = [3]u16{ 0xFD87, 0xD87E, 0xEB43 };

fn isIpv4Mapped(addr: [8]u16) bool {
    return mem.eql(u16, addr[0..6], &[6]u16{ 0, 0, 0, 0, 0, 0xFFFF });
}

fn ipv4ToIpv6Mapped(ipv4: [4]u8) [8]u16 {
    return [8]u16{ 0, 0, 0, 0, 0, 0xFFFF, @as(u16, ipv4[0]) << 8 | ipv4[1], @as(u16, ipv4[2]) << 8 | ipv4[3] };
}

fn ipv6MappedToIpv4(addr: [8]u16) [4]u8 {
    return [4]u8{
        @as(u8, addr[6] >> 8), @as(u8, addr[6] & 0xFF),
        @as(u8, addr[7] >> 8), @as(u8, addr[7] & 0xFF),
    };
}

// 测试代码
const testing = std.testing;

pub fn testSerializeAddress() !void {
    const addr = Address{
        .services = 1,
        .address = [8]u16{ 0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0001 },
        .port = 8333,
    };
    try testing.expectEqual(addr.services, 1);
    try testing.expectEqual(addr.port, 8333);
}

pub fn testDeserializeAddress() !void {
    const addr = Address{
        .services = 1,
        .address = [8]u16{ 0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0001 },
        .port = 8333,
    };
    try testing.expectEqual(addr.services, 1);
    try testing.expectEqual(addr.port, 8333);
}

pub fn testSocketAddr() !void {
    const ipv4 = net.Address.initIp4([4]u8{ 111, 222, 123, 4 }, 5555);
    const s4 = net.Address{ .in = ipv4.in };
    const a4 = Address.new(s4, 9);
    try testing.expectEqual(a4.socketAddr() catch unreachable, s4);

    const s6 = net.Address{ .ipv6 = .{ .address = [8]u16{ 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888 }, .port = 9999 } };
    const a6 = Address.new(s6, 9);
    try testing.expectEqual(a6.socketAddr() catch unreachable, s6);
}

pub fn testOnionAddress() !void {
    const onion_addr = Address{
        .services = 0,
        .address = [8]u16{ 0xFD87, 0xD87E, 0xEB43, 0, 0, 0, 0, 1 },
        .port = 9050,
    };
    try testing.expectError(error.AddrNotAvailable, onion_addr.socketAddr());
}

test "test v4 to v6" {
    try testDeserializeAddress();
    try testSerializeAddress();
    try testSocketAddr();
}
