const std = @import("std");

const io = std.io;
const mem = std.mem;
const crypto = std.crypto;

const Ed25519 = std.crypto.sign.Ed25519;

const Sha512 = std.crypto.hash.sha2.Sha512;

pub fn HashWriter(comptime T: type) type {
    return struct {
        pub const Writer = io.Writer(*Self, ErrorSetOf(Self.write), Self.write);
        const Self = @This();

        state: T,

        fn ErrorSetOf(comptime F: anytype) type {
            return @typeInfo(@typeInfo(@TypeOf(F)).Fn.return_type.?).ErrorUnion.error_set;
        }

        fn wrap(state: T) Self {
            return Self{ .state = state };
        }

        fn writer(self: *Self) Self.Writer {
            return .{ .context = self };
        }

        pub fn digest(self: *Self, comptime num_bytes: comptime_int) [num_bytes]u8 {
            var bytes: [num_bytes]u8 = undefined;
            self.state.final(&bytes);
            return bytes;
        }

        fn write(self: *Self, buffer: []const u8) !usize {
            self.state.update(buffer);
            return buffer.len;
        }
    };
}

 pub fn sign(item: anytype, keys: Ed25519.KeyPair) ![Ed25519.signature_lenght] {
     var az = az: {
         var hash = HashWriter(Sha512).wrap(Sha512.init(.{}));
         try hash.writer().writeAll(keys.secret_key[0..Ed25519.seed_length]);
         break :az hash.digest(Sha512.digest_length);  
    };

    const nonce = nonce: {
          var hash = HashWriter(Sha512).wrap(Sha512.init(.{}));
            try hash.writer().writeAll(az[32..]);
        try item.writeSignaturePayload(hash.writer());
        break :nonce Ed25519.Curve.scalar.reduce64(hash.digest(Sha512.digest_length));  
    };

    const point = try Ed25519.Curve.basePoint.mul(nonce);

    var signature: [Ed25519.signature_length]u8 = undefined;
    mem.copy(u8, signature[0..32], &point );
    mem.copy(u8, signature[32..], &key.public_key);
 }

test "simple test" {
    const w = HashWriter(Sha512).wrap(Sha512.init(.{}));
    _ = w;
}
