const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const rotl = std.math.rotl;
const AesBlock = std.crypto.core.aes.Block;
const AuthenticationError = std.crypto.errors.AuthenticationError;
const Lane = std.meta.Vector(4, u64);

pub const Morus = struct {
    pub const tag_length = 16;
    pub const nonce_length = 16;
    pub const key_length = 16;

    const State = [5]Lane;

    s: State,

    fn update(self: *Morus, input: Lane) void {
        const s = &self.s;
        s[0] = s[0] ^ s[3];
        s[0] = s[0] ^ (s[1] & s[2]);
        s[0] = rotl(Lane, s[0], 13);
        var t = Lane{ s[3][3], s[3][0], s[3][1], s[3][2] };
        s[3] = t;

        s[1] = s[1] ^ input;
        s[1] = s[1] ^ s[4];
        s[1] = s[1] ^ (s[2] & s[3]);
        s[1] = rotl(Lane, s[1], 46);
        t = Lane{ s[4][2], s[4][3], s[4][0], s[4][1] };
        s[4] = t;

        s[2] = s[2] ^ input;
        s[2] = s[2] ^ s[0];
        s[2] = s[2] ^ (s[3] & s[4]);
        s[2] = rotl(Lane, s[2], 38);
        t = Lane{ s[0][1], s[0][2], s[0][3], s[0][0] };
        s[0] = t;

        s[3] = s[3] ^ input;
        s[3] = s[3] ^ s[1];
        s[3] = s[3] ^ (s[4] & s[0]);
        s[3] = rotl(Lane, s[3], 7);
        t = Lane{ s[1][2], s[1][3], s[1][0], s[1][1] };
        s[1] = t;

        s[4] = s[4] ^ input;
        s[4] = s[4] ^ s[2];
        s[4] = s[4] ^ (s[0] & s[1]);
        s[4] = rotl(Lane, s[4], 4);
        t = Lane{ s[2][3], s[2][0], s[2][1], s[2][2] };
        s[2] = t;
    }

    fn init(k: [16]u8, iv: [16]u8) Morus {
        const c = [_]u8{
            0x0,  0x1,  0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9,
            0x79, 0x62, 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42,
            0x73, 0xb5, 0x28, 0xdd,
        };
        const k0 = mem.readIntLittle(u64, k[0..8]);
        const k1 = mem.readIntLittle(u64, k[8..16]);
        const iv0 = mem.readIntLittle(u64, iv[0..8]);
        const iv1 = mem.readIntLittle(u64, iv[8..16]);
        const v0 = Lane{ iv0, iv1, 0, 0 };
        const v1 = Lane{ k0, k1, k0, k1 };
        const v2 = @splat(4, ~@as(u64, 0));
        const v3 = @splat(4, @as(u64, 0));
        const v4 = Lane{
            mem.readIntLittle(u64, c[0..8]),
            mem.readIntLittle(u64, c[8..16]),
            mem.readIntLittle(u64, c[16..24]),
            mem.readIntLittle(u64, c[24..32]),
        };
        var self = Morus{ .s = State{ v0, v1, v2, v3, v4 } };
        var i: usize = 0;
        const zero = @splat(4, @as(u64, 0));
        while (i < 16) : (i += 1) {
            self.update(zero);
        }
        self.s[1] ^= v1;
        return self;
    }

    fn enc(self: *Morus, xi: *const [32]u8) [32]u8 {
        const p = Lane{
            mem.readIntLittle(u64, xi[0..8]),
            mem.readIntLittle(u64, xi[8..16]),
            mem.readIntLittle(u64, xi[16..24]),
            mem.readIntLittle(u64, xi[24..32]),
        };
        const s = self.s;
        const c = p ^ s[0] ^ Lane{ s[1][1], s[1][2], s[1][3], s[1][0] } ^ (s[2] & s[3]);
        var ci: [32]u8 = undefined;
        mem.writeIntLittle(u64, ci[0..8], c[0]);
        mem.writeIntLittle(u64, ci[8..16], c[1]);
        mem.writeIntLittle(u64, ci[16..24], c[2]);
        mem.writeIntLittle(u64, ci[24..32], c[3]);
        self.update(p);
        return ci;
    }

    fn dec(self: *Morus, ci: *const [32]u8) [32]u8 {
        const c = Lane{
            mem.readIntLittle(u64, ci[0..8]),
            mem.readIntLittle(u64, ci[8..16]),
            mem.readIntLittle(u64, ci[16..24]),
            mem.readIntLittle(u64, ci[24..32]),
        };
        const s = self.s;
        const p = c ^ s[0] ^ Lane{ s[1][1], s[1][2], s[1][3], s[1][0] } ^ (s[2] & s[3]);
        var xi: [32]u8 = undefined;
        mem.writeIntLittle(u64, xi[0..8], p[0]);
        mem.writeIntLittle(u64, xi[8..16], p[1]);
        mem.writeIntLittle(u64, xi[16..24], p[2]);
        mem.writeIntLittle(u64, xi[24..32], p[3]);
        self.update(p);
        return xi;
    }

    fn decLast(self: *Morus, xn: []u8, cn: []const u8) void {
        var pad = [_]u8{0} ** 32;
        mem.copy(u8, pad[0..cn.len], cn);
        const c = Lane{
            mem.readIntLittle(u64, pad[0..8]),
            mem.readIntLittle(u64, pad[8..16]),
            mem.readIntLittle(u64, pad[16..24]),
            mem.readIntLittle(u64, pad[24..32]),
        };
        const s = self.s;
        var p = c ^ s[0] ^ Lane{ s[1][1], s[1][2], s[1][3], s[1][0] } ^ (s[2] & s[3]);
        mem.writeIntLittle(u64, pad[0..8], p[0]);
        mem.writeIntLittle(u64, pad[8..16], p[1]);
        mem.writeIntLittle(u64, pad[16..24], p[2]);
        mem.writeIntLittle(u64, pad[24..32], p[3]);
        mem.set(u8, pad[cn.len..], 0);
        mem.copy(u8, xn, pad[0..cn.len]);
        p = Lane{
            mem.readIntLittle(u64, pad[0..8]),
            mem.readIntLittle(u64, pad[8..16]),
            mem.readIntLittle(u64, pad[16..24]),
            mem.readIntLittle(u64, pad[24..32]),
        };
        self.update(p);
    }

    fn finalize(self: *Morus, adlen: usize, mlen: usize) [16]u8 {
        const t = [4]u64{ @intCast(u64, adlen) * 8, @intCast(u64, mlen) * 8, 0, 0 };
        var s = &self.s;
        s[4] ^= s[0];
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            self.update(t);
        }
        s = &self.s;
        s[0] ^= Lane{ s[1][1], s[1][2], s[1][3], s[1][0] } ^ (s[2] & s[3]);
        var tag: [16]u8 = undefined;
        mem.writeIntLittle(u64, tag[0..8], s[0][0]);
        mem.writeIntLittle(u64, tag[8..16], s[0][1]);
        return tag;
    }

    pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, iv: [nonce_length]u8, k: [key_length]u8) void {
        assert(c.len == m.len);
        var morus = init(k, iv);

        var i: usize = 0;
        while (i + 32 <= ad.len) : (i += 32) {
            _ = morus.enc(ad[i..][0..32]);
        }
        if (ad.len % 32 != 0) {
            var pad = [_]u8{0} ** 32;
            mem.copy(u8, pad[0 .. ad.len % 32], ad[i..]);
            _ = morus.enc(&pad);
        }

        i = 0;
        while (i + 32 <= m.len) : (i += 32) {
            mem.copy(u8, c[i..][0..32], &morus.enc(m[i..][0..32]));
        }
        if (m.len % 32 != 0) {
            var pad = [_]u8{0} ** 32;
            mem.copy(u8, pad[0 .. m.len % 32], m[i..]);
            mem.copy(u8, c[i..], morus.enc(&pad)[0 .. m.len % 32]);
        }

        tag.* = morus.finalize(ad.len, m.len);
    }

    pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, iv: [nonce_length]u8, k: [key_length]u8) AuthenticationError!void {
        assert(c.len == m.len);
        var morus = init(k, iv);

        var i: usize = 0;
        while (i + 32 <= ad.len) : (i += 32) {
            _ = morus.enc(ad[i..][0..32]);
        }
        if (ad.len % 32 != 0) {
            var pad = [_]u8{0} ** 32;
            mem.copy(u8, pad[0 .. ad.len % 32], ad[i..]);
            _ = morus.enc(&pad);
        }

        i = 0;
        while (i + 32 <= c.len) : (i += 32) {
            mem.copy(u8, m[i..][0..32], &morus.dec(c[i..][0..32]));
        }
        if (c.len % 32 != 0) {
            morus.decLast(m[i..], c[i..]);
        }

        const expected_tag = morus.finalize(ad.len, m.len);
        if (!crypto.utils.timingSafeEql([expected_tag.len]u8, expected_tag, tag)) {
            return error.AuthenticationFailed;
        }
    }
};

const testing = std.testing;
const fmt = std.fmt;

test "morus" {
    const k = "YELLOW SUBMARINE".*;
    const iv = [_]u8{0} ** 16;
    const ad = "Comment numero un";
    var m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var expected_tag: [Morus.tag_length]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_tag, "fe0bf3ea600b0355eb535ddd35320e1b");
    var expected_c: [m.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_c, "712ae984433ceea0448a6a4f35afd46b42f42d69316e42aa54264dfd8951293b6ed676c9a813e7f42745e6210de9c82c4ac67fde57695c2d1e1f2f302682f118c6895915de8fa63de1bb798c7a178ce3290dfe3527c370a4c65be01ca55b7abb26b573ade9076cbf9b8c06acc750470a4524");
    var tag: [16]u8 = undefined;
    Morus.encrypt(&c, &tag, m, ad, iv, k);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);
    try testing.expectEqualSlices(u8, &expected_c, &c);
    try Morus.decrypt(&m2, &c, tag, ad, iv, k);
    try testing.expectEqualSlices(u8, m, &m2);
}
