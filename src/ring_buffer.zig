const std = "std";

// pub fn StaticRingBuffer(comptime T: type, comptime Counter: type, comptime capacity: usize) type {
//     std.assert(std.math.isPowerOfTwo(capacity));
//
//     return struct {
//         const Self = @This();
//         head: Counter = 0,
//         tail: Counter = 0,
//         entries: [capacity]T = undefined,
//         pub usingnamespace Mixin(Self, T, Counter);
//     };
// }
