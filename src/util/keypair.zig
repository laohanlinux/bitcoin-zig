const std = @import("std");
const crypto = std.crypto;
const Secp256k1 = crypto.ecc.Secp256k1;

// 密钥对结构
const KeyPair = struct {
    private_key: [32]u8,
    public_key: [33]u8, // 压缩格式的公钥
};

// 签名结构
const Signature = struct {
    r: [32]u8,
    s: [32]u8,
};

// 生成密钥对
pub fn generateKeyPair(allocator: std.mem.Allocator) !KeyPair {
    // 1. 生成私钥 (随机32字节)
    var private_key: [32]u8 = undefined;
    try crypto.randomBytes(&private_key);

    // 2. 确保私钥在合法范围内 (小于曲线阶数)
    while (Secp256k1.scalar.isCanonical(private_key) == false) {
        try crypto.randomBytes(&private_key);
    }

    // 3. 计算公钥 (G * private_key)
    const public_point = try Secp256k1.basePoint.mul(private_key, .little);

    // 4. 将公钥转换为压缩格式
    const public_key = public_point.toCompressedSec1();

    return KeyPair{
        .private_key = private_key,
        .public_key = public_key,
    };
}

// 签名消息
pub fn sign(msg: []const u8, private_key: [32]u8) !Signature {
    // 1. 生成随机数 k (RFC6979 确定性生成)
    var k: [32]u8 = undefined;
    try crypto.randomBytes(&k);
    while (Secp256k1.scalar.isCanonical(k) == false) {
        try crypto.randomBytes(&k);
    }

    // 2. 计算 R = k*G，取 x 坐标作为 r
    const R = try Secp256k1.basePoint.mul(k, .little);
    const r = R.affineCoordinates().x.toBytes(.big);

    // 3. 计算消息哈希
    var h: [32]u8 = undefined;
    var hasher = crypto.hash.sha256.init();
    hasher.update(msg);
    hasher.final(&h);

    // 4. 计算 s = k^(-1) * (h + r*private_key) mod n
    const k_inv = try Secp256k1.scalar.invert(k);
    const h_plus_rd = try Secp256k1.scalar.mulAdd(r, private_key, h, .big);
    const s = try Secp256k1.scalar.mul(k_inv, h_plus_rd, .big);

    return Signature{
        .r = r,
        .s = s,
    };
}

// 验证签名
pub fn verify(msg: []const u8, sig: Signature, public_key: [33]u8) !bool {
    // 1. 解析公钥
    const public_point = try Secp256k1.fromSec1(&public_key);

    // 2. 计算消息哈希
    var h: [32]u8 = undefined;
    var hasher = crypto.hash.sha256.init();
    hasher.update(msg);
    hasher.final(&h);

    // 3. 计算 s^(-1)
    const s_inv = try Secp256k1.scalar.invert(sig.s);

    // 4. 计算 u1 = h * s^(-1) mod n
    const u1 = try Secp256k1.scalar.mul(h, s_inv, .big);

    // 5. 计算 u2 = r * s^(-1) mod n
    const u2 = try Secp256k1.scalar.mul(sig.r, s_inv, .big);

    // 6. 计算 R' = u1*G + u2*public_key
    const R_prime = try Secp256k1.mulDoubleBasePublic(Secp256k1.basePoint, u1, public_point, u2, .big);

    // 7. 验证 R'.x == r
    const r_prime = R_prime.affineCoordinates().x.toBytes(.big);
    return std.mem.eql(u8, &r_prime, &sig.r);
}

// 使用示例
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 生成密钥对
    const key_pair = try generateKeyPair(allocator);

    // 待签名消息
    const message = "Hello, Secp256k1!";

    // 签名
    const signature = try sign(message, key_pair.private_key);

    // 验证
    const is_valid = try verify(message, signature, key_pair.public_key);

    std.debug.print("Signature valid: {}\n", .{is_valid});
}
