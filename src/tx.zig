const std = @import("std");
const big = @import("std").math.big;
const script = @import("./blockdata/script/script.zig");

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
    prev_out: OutPoint,
    script_sig: ?script.Script,
    sequence: isize,
    const Self = @This();

    pub fn init(prev_out: OutPoint, script_sig: ?script.Script, sequence: isize) Self {
        return Self{ .prev_out = prev_out, .script_sig = script_sig, .sequence = sequence };
    }
};

// An output of a transaction. It contains the public key that the next input
// must be signed with to claim it.
pub const TxOut = struct {
    n_value: i64,
    script_pub_key: ?script.Script,
    const Self = @This();

    pub fn init(value: i64, script_pub_key: ?script.Script) Self {
        return Self{ .n_value = value, .script_pub_key = script_pub_key };
    }
};

pub const InPoint = struct {
    ptx: ?Transaction,
    n: isize,
    const Self = @This();
    pub fn init(tx: *Transaction, n: isize) !Self {
        return Self{ .ptx = tx, .n = n };
    }

    pub fn set_null(self: *Self) void {
        self.ptx = null;
        self.n = -1;
    }

    pub fn is_null(self: *Self) bool {
        return (self.ptx == null and self.n == -1);
    }

    // pub fn to_string(self: *Self) ![]u8 {
    //     if (self.is_null()) {
    //         return "InPoint(null, -1)";
    //     }
    //     const str = try std.fmt.allocPrint(self.allocator, "InPoint({any}, {any})", .{self.ptx, self.n});
    //     return str;
    // }
};
pub const OutPoint = struct {
    n: isize,
    hash: big.int.Const,
    bigManaged: big.int.Managed,

    const Self = @This();
    pub fn init(n: isize, allocator: std.mem.Allocator) !Self {
        const m = big.int.Managed.initSet(allocator, 0) catch unreachable;
        return Self{ .hash = m.toConst(), .n = n, .bigManaged = m };
    }

    pub fn deinit(self: *Self) void {
        self.bigManaged.deinit();
    }

    pub fn set_null(self: *Self) void {
        self.n = -1;
        self.bigManaged.set(0) catch unreachable;
        self.hash = self.bigManaged.toConst();
    }

    pub fn is_null(self: *Self) bool {
        return (self.n == -1 and self.hash.eqlZero());
    }

    pub fn to_string(self: *Self, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const str_hash = try self.hash.toStringAlloc(allocator, 16, std.fmt.Case.lower);
        defer allocator.free(str_hash);
        const str = try std.fmt.allocPrint(allocator, "OutPoint({any}, {any})", .{ str_hash, self.n });
        return str;
    }
};

test "bigint" {
    const Managed = std.math.big.int.Managed;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var a = try Managed.init(allocator);
    var b = try Managed.init(allocator);

    try a.set(1990273423429836742364234234234);
    try b.set(1990273423429836742364234234234);

    try a.add(&a, &b);
    std.debug.print("{any}\n", .{a});

    try a.mul(&a, &b);
    std.debug.print("{any}\n", .{a});
    var out = try OutPoint.init(0, std.testing.allocator);
    defer out.deinit();
    std.debug.print("{any}\n", .{out.is_null()});
    out.set_null();
    std.debug.print("{any}\n", .{out.is_null()});

    const out_str = try out.to_string(std.testing.allocator);
    defer std.testing.allocator.free(out_str);
    std.debug.print("{s}\n", .{out_str});
}
