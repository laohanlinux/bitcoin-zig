const std = @import("std");
const meta = std.meta;
const mem = std.mem;
const math = std.math;
const testing = std.testing;
const assert = std.debug.assert;

/// A double-ended doubly-linked list (doubly-linked deque). Keeps track of two pointers: one head pointer, and one tail pointer.
pub fn DoublyLinkedDeque(comptime T: type, comptime next_field: anytype, comptime pre_field: anytype) type {
    const next = meta.fieldInfo(T, next_field).name;
    const prev = meta.fieldInfo(T, pre_field).name;

    return struct {
        const Self = @This();
        head: ?*T = null,
        tail: ?*T = null,

        pub fn isEmpty(self: *const Self) bool {
            return self.head == null;
        }

        pub fn prepend(self: *Self, value: *T) void {
            if (self.head) |head| {
                if (head == value) return;
                @field(head, prev) = value;
            } else {
                self.tail = value;
            }
            @field(value, prev) = null;
            @field(value, next) = self.head;
            self.head = value;
        }

        pub fn append(self: *Self, value: *T) void {
            if (self.tail) |tail| {
                if (tail == value) return;
                @field(tail, next) = value;
            } else {
                self.head = value;
            }

            @field(value, prev) = self.tail;
            @field(value, next) = null;
            self.tail = value;
        }

        pub fn concat(self: *Self, other: Self) void {
            if (self.tail) |tail| {
                @field(tail, next) = other.head;
                if (other.head) |other_head| {
                    @field(other_head, prev) = self.tail;
                }
            } else {
                self.head = other.head;
            }
            self.tail = other.tail;
        }

        pub fn popFirst(self: *Self) ?*T {
            const head = self.head orelse return null;
            if (@field(head, next)) |next_value| {
                @field(next_value, prev) = null;
            } else {
                self.tail = null;
            }
            self.head = @field(head, next);
            @field(head, next) = null;
            @field(head, prev) = null;
            return head;
        }

        pub fn pop(self: *Self) ?*T {
            const tail = self.tail orelse return null;
            if (@field(tail, prev)) |prev_value| {
                @field(prev_value, next) = null;
            } else {
                self.head = null;
            }

            self.tail = @field(tail, prev);
            @field(tail, next) = null;
            @field(tail, prev) = null;
            return tail;
        }

        pub fn remove(self: *Self, value: *T) bool {
            if (self.head == null) {
                return false;
            }
            if (self.head != value and @field(value, next) == null and @field(value, prev) == null) {
                return false;
            }
            if (@field(value, next)) |next_value| {
                @field(next_value, prev) = @field(value, prev);
            } else {
                self.tail = @field(value, prev);
            }
            if (@field(value, prev)) |prev_value| {
                @field(prev_value, next) = @field(value, next);
            } else {
                self.head = @field(value, next);
            }

            @field(value, next) = null;
            @field(value, prev) = null;

            return true;
        }
    };
}
