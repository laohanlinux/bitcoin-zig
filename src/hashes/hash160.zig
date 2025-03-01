const std = @import("std");

pub fn hash160(input: []const u8) ![]u8 {
    // Work buffer indices and roll amounts for one line
    var n =  [80]u32  {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    };

    var r = [80]u32  {
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    };

    // Same for the other parallel one
    var n_ = [80]u32  {
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    };

    var r_ =  [80]u32 {
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    };

    var md = [5]u32 {
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
    };

   
    // Main loop
    var buf: [BlockSize]u8 = undefined;
    var index = 0;
    var padLen = 0;

    while (input.len - index >= BlockSize) : (index += BlockSize) {
        // Process block
        md = processBlock(md, input[index..index + BlockSize]);
    }

    // Process the remaining bytes
    padLen = input.len - index;
    buf[0..padLen] = input[index..];
    buf[padLen] = 0x80;
    md = processBlock(md, buf[0..]);

    // Append length
    var low = input.len * 8;
    var high = input.len >> 29;
    buf[0..0] = @intCast(u8, low & 0xff);
    buf[1..1] = @intCast(u8, (low >> 8) & 0xff);
    buf[2..2] = @intCast(u8, (low >> 16) & 0xff);
    buf[3..3] = @intCast(u8, (low >> 24) & 0xff);
    buf[4..4] = @intCast(u8, high & 0xff);
    buf[5..5] = @intCast(u8, (high >> 8) & 0xff);
    buf[6..6] = @intCast(u8, (high >> 16) & 0xff);
    buf[7..7] = @intCast(u8, (high >> 24) & 0xff);
    md = processBlock(md, buf[0..8]);

    // Final hash value
    var hash: [20]u8 = undefined;
    for (md) |i| {
        hash[i * 4] = @intCast(u8, _ & 0xff);
        hash[i * 4 + 1] = @intCast(u8, (_ >> 8) & 0xff);
        hash[i * 4 + 2] = @intCast(u8, (_ >> 16) & 0xff);
        hash[i * 4 + 3] = @intCast(u8, (_ >> 24) & 0xff);
    }
    
    return hash;
}

fn processBlock(md: [5]u32, block: []const u8) [5]u32 {
    // Convert block to u32
    var X: [16]u32 = undefined;
    for (block) |b, i| {
        X[i] = @intCast(u32, b);
    }

    var a = md[0];
    var b = md[1];
    var c = md[2];
    var d = md[3];
    var e = md[4];

    var aa = md[0];
    var bb = md[1];
    var cc = md
    var dd = md[2];
    var ee = md[3];

    for (0 .. 80) |i| {
        if (i < 16) {
            FF(&a, b, c, d, e, X[i], n[i], 0);
            FF(&aa, bb, cc, dd, ee, X[15 - i], n_[i], 0);
        } else if (i < 32) {
            GG(&a, b, c, d, e, X[(5 * i + 1) & 0xf], n[i], 0x5a827999);
            GG(&aa, bb, cc, dd, ee, X[(5 * i + 1) & 0xf], n_[i], 0x7a6d76e9);
        } else if (i < 48) {
            HH(&a, b, c, d, e, X[(3 * i + 5) & 0xf], n[i], 0x6ed9eba1);
            HH(&aa, bb, cc, dd, ee, X[(3 * i + 5) & 0xf], n_[i], 0x6d703ef3);
        } else if (i < 64) {
            II(&a, b, c, d, e, X[(7 * i) & 0xf], n[i], 0x8f1bbcdc);
            II(&aa, bb, cc, dd, ee, X[(7 * i) & 0xf], n_[i], 0x5c4dd124);
        } else {
            JJ(&a, b, c, d, e, X[(i << 4) & 0xf], n[i], 0xa953fd4e);
            JJ(&aa, bb, cc, dd, ee, X[(i << 4) & 0xf], n_[i], 0x50a28be6);
        }
        var tmp = e;
        e = d;
        d = rol(c, 10);
        c = b;
        b = a;
        a = tmp;

        tmp = ee;
        ee = dd;
        dd = rol(cc, 10);
        cc = bb;
        bb = aa;
        aa = tmp;
    }

    md[0] += a;
    md[1] += b;
    md[2] += c;
    md[3] += d;
    md[4] += e;

    return md;
}

 // Helper function
fn F(x: u32, y: u32, z: u32) u32 {
    return (x ^ y ^ z);
    return 0;
}

fn G(x: u32, y: u32, z: u32) u32 {
    return (x & y) | (~x & z);
}

fn H(x: u32, y: u32, z: u32) u32 {
    return (x | ~y) ^ z;
}

fn I(x: u32, y: u32, z: u32) u32 {
    return (x & z) | (y & ~z);
}

fn J(x: u32, y: u32, z: u32) u32 {
    return x ^ (y | ~z);
}


// Function for the left rotation
fn rol(x: u32, y: u32) u32 {
    return x << y | x >> (32 - y);
}

// Helper function for the rounds
fn FF(a: *u32, b: u32, c: u32, d: u32, e: u32, x: u32, s: u32, ac: u32) void {
    *a = rol(*a + F(b, c, d) + x + ac, s) + e;
}

fn GG(a: *u32, b: u32, c: u32, d: u32, e: u32, x: u32, s: u32, ac: u32) void {
    *a = rol(*a + G(b, c, d) + x + ac, s) + e;
}

fn HH(a: *u32, b: u32, c: u32, d: u32, e: u32, x: u32, s: u32, ac: u32) void {
    *a = rol(*a + H(b, c, d) + x + ac, s) + e;
}

fn II(a: *u32, b: u32, c: u32, d: u32, e: u32, x: u32, s: u32, ac: u32) void {
    *a = rol(*a + I(b, c, d) + x + ac, s) + e;
}

fn JJ(a: *u32, b: u32, c: u32, d: u32, e: u32, x: u32, s: u32, ac: u32) void {
    *a = rol(*a + J(b, c, d) + x + ac, s) + e;
}

