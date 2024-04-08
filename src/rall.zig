const std = @import("std");

pub fn AutoRef(comptime T: type) type {
    return struct {
        ref: std.atomic.Value(i64),
        inner: T,

        const Self = @This();
        pub fn init(t: T) Self {
            return .{ .ref = std.atomic.Value(i64).init(1), .inner = t };
        }

        pub fn clone(self: *Self) *Self {
            _ = self.ref.fetchAdd(1, std.builtin.AtomicOrder.seq_cst);
            return self;
        }

        pub fn toOwner(self: Self) T {
            return self.inner;
        }

        pub fn deinit(self: *Self) void {
            const ref = self.ref.fetchSub(1, std.builtin.AtomicOrder.seq_cst);
            std.debug.print("count is {}\n", .{ref});
            if (ref == 1) {
                self.inner.deinit();
            }
        }
    };
}

test "Reference" {
    const demo = struct {
        const Self = @This();
        fn deinit(self: *Self) void {
            _ = self;
            std.debug.print("call deinit\n", .{});
        }
    };
    var auto = AutoRef(demo).init(.{});
    defer auto.deinit();
    {
        var a1 = auto.clone();
        defer a1.deinit();
    }
}
