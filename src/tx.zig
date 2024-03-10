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

pub const OutPoint = struct {
    n: isize,
    hash: big.int.Const,
    const Self = @This();

    pub fn set_null(self: *Self) void {
        self.n = -1;
        self.hash = big.Const(0);
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
}
