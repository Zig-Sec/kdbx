const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;
const math = std.math;
const mem = std.mem;
const assert = std.debug.assert;
const testing = std.testing;
const maxInt = math.maxInt;

pub const ChaCha20 = struct {
    ctx: BlockVec,
    x: BlockVec,
    left: usize,
    buffer: [64]u8,

    const BlockVec = [16]u32;

    /// Nonce length in bytes.
    pub const nonce_length = 12;
    /// Key length in bytes.
    pub const key_length = 32;
    /// Block length in bytes.
    pub const block_length = 64;
    pub const rounds_nb = 20;

    pub fn init(counter: u32, key_: [key_length]u8, nonce: [nonce_length]u8) @This() {
        var d: [4]u32 = undefined;
        d[0] = counter;
        d[1] = mem.readInt(u32, nonce[0..4], .little);
        d[2] = mem.readInt(u32, nonce[4..8], .little);
        d[3] = mem.readInt(u32, nonce[8..12], .little);

        const key = keyToWords(key_);

        const c = "expand 32-byte k";
        const constant_le = comptime [4]u32{
            mem.readInt(u32, c[0..4], .little),
            mem.readInt(u32, c[4..8], .little),
            mem.readInt(u32, c[8..12], .little),
            mem.readInt(u32, c[12..16], .little),
        };
        return .{
            .ctx = .{
                constant_le[0], constant_le[1], constant_le[2], constant_le[3],
                key[0],         key[1],         key[2],         key[3],
                key[4],         key[5],         key[6],         key[7],
                d[0],           d[1],           d[2],           d[3],
            },
            .x = .{0} ** 16,
            .left = 0,
            .buffer = undefined,
        };
    }

    pub fn xor(self: *@This(), out: []u8) void {
        var k: usize = 0;

        while (k < out.len) {
            if (self.left == 0) {
                chacha20Core(self.x[0..], self.ctx);
                contextFeedback(&self.x, self.ctx);
                hashToBytes(self.buffer[0..64], self.x);
                self.left = 64;
                self.ctx[12] +%= 1;
            }

            out[k] ^= self.buffer[64 - self.left];
            k += 1;
            self.left -= 1;
        }
    }

    const QuarterRound = struct {
        a: usize,
        b: usize,
        c: usize,
        d: usize,
    };

    fn Rp(a: usize, b: usize, c: usize, d: usize) QuarterRound {
        return QuarterRound{
            .a = a,
            .b = b,
            .c = c,
            .d = d,
        };
    }

    inline fn chacha20Core(x: *BlockVec, input: BlockVec) void {
        x.* = input;

        const rounds = comptime [_]QuarterRound{
            Rp(0, 4, 8, 12),
            Rp(1, 5, 9, 13),
            Rp(2, 6, 10, 14),
            Rp(3, 7, 11, 15),
            Rp(0, 5, 10, 15),
            Rp(1, 6, 11, 12),
            Rp(2, 7, 8, 13),
            Rp(3, 4, 9, 14),
        };

        comptime var j: usize = 0;
        inline while (j < rounds_nb) : (j += 2) {
            inline for (rounds) |r| {
                x[r.a] +%= x[r.b];
                x[r.d] = math.rotl(u32, x[r.d] ^ x[r.a], @as(u32, 16));
                x[r.c] +%= x[r.d];
                x[r.b] = math.rotl(u32, x[r.b] ^ x[r.c], @as(u32, 12));
                x[r.a] +%= x[r.b];
                x[r.d] = math.rotl(u32, x[r.d] ^ x[r.a], @as(u32, 8));
                x[r.c] +%= x[r.d];
                x[r.b] = math.rotl(u32, x[r.b] ^ x[r.c], @as(u32, 7));
            }
        }
    }

    inline fn hashToBytes(out: *[64]u8, x: BlockVec) void {
        for (0..4) |i| {
            mem.writeInt(u32, out[16 * i + 0 ..][0..4], x[i * 4 + 0], .little);
            mem.writeInt(u32, out[16 * i + 4 ..][0..4], x[i * 4 + 1], .little);
            mem.writeInt(u32, out[16 * i + 8 ..][0..4], x[i * 4 + 2], .little);
            mem.writeInt(u32, out[16 * i + 12 ..][0..4], x[i * 4 + 3], .little);
        }
    }

    inline fn contextFeedback(x: *BlockVec, ctx: BlockVec) void {
        for (0..16) |i| {
            x[i] +%= ctx[i];
        }
    }
};

fn keyToWords(key: [32]u8) [8]u32 {
    var k: [8]u32 = undefined;
    for (0..8) |i| {
        k[i] = mem.readInt(u32, key[i * 4 ..][0..4], .little);
    }
    return k;
}
