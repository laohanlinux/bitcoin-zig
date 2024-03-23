const std = @import("std");
const big = @import("std").math.big;

//
// The basic transation that is broadcasted on the network and contained in
// blocks. A transaction can contian multiple inputs and outputs.
//
pub const Transaction = struct {
    n_version: isize,
};

//
// An input of a transaction. It contains the location of the previous
// transaction's input that it claims and a signature that matches the
// output's public key.
//
pub const TxIn = struct {
    const self = @This();
};

//
pub const OutPoint = struct {
    n: isize,
    hash: big.int.Const,
    allocator: std.mem.Allocator,
    const Self = @This();
    pub fn new(n: isize, allocator: std.mem.Allocator) !Self {
        const m = big.int.Managed.initSet(allocator, 0) catch unreachable;
        return Self{ .hash = m.toConst(), .n = n, .allocator = allocator };
    }

    pub fn set_null(self: *Self) void {
        self.n = -1;
        const m = big.int.Managed.initSet(self.allocator, 0) catch unreachable;
        self.hash = m.toConst();
    }

    pub fn is_null(self: *Self) bool {
        return (self.n == -1 and self.hash.eqlZero());
    }
};

test "bigint" {
    const Managed = std.math.big.int.Managed;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();

    var a = try Managed.init(allocator);
    var b = try Managed.init(allocator);

    try a.set(1990273423429836742364234234234);
    try b.set(1990273423429836742364234234234);

    try a.add(&a, &b);
    std.debug.print("{any}\n", .{a});

    try a.mul(&a, &b);
    std.debug.print("{any}\n", .{a});
    var out = try OutPoint.new(0, gpa.allocator());
    std.debug.print("{any}\n", .{out.is_null()});
    out.set_null();
    std.debug.print("{any}\n", .{out.is_null()});
}
