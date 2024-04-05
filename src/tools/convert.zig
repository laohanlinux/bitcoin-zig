
pub fn usizeToU8(n: usize) u8 {
    return @as(u8, @truncate(n));
}