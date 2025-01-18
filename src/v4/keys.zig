const std = @import("std");

pub const Keys = struct {
    ekey: [32]u8 = .{0} ** 32,
    mkey: [64]u8 = .{0} ** 64,

    pub fn deinit(self: *@This()) void {
        std.crypto.utils.secureZero(u8, &self.ekey);
        std.crypto.utils.secureZero(u8, &self.mkey);
    }

    pub fn getBlockKey(self: *const @This(), index: u64) [64]u8 {
        var block_index: [8]u8 = .{0} ** 8;
        std.mem.writeInt(u64, &block_index, index, .little);
        var k: [64]u8 = .{0} ** 64;

        var h = std.crypto.hash.sha2.Sha512.init(.{});
        h.update(&block_index);
        h.update(&self.mkey);
        h.final(&k);

        return k;
    }

    pub fn calculateMac(
        self: *const @This(),
        data: []const []const u8,
        index: u64,
    ) [32]u8 {
        var k = self.getBlockKey(index);
        defer std.crypto.utils.secureZero(u8, &k);

        const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
        var mac: [HmacSha256.mac_length]u8 = undefined;
        var ctx = HmacSha256.init(&k);
        for (data) |d| {
            ctx.update(d);
        }
        ctx.final(&mac);

        return mac;
    }

    pub fn checkMac(
        self: *const @This(),
        expected: []const u8,
        data: []const []const u8,
        index: u64,
    ) !void {
        var k = self.getBlockKey(index);
        defer std.crypto.utils.secureZero(u8, &k);

        const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
        var mac: [HmacSha256.mac_length]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &mac);
        var ctx = HmacSha256.init(&k);
        for (data) |d| {
            ctx.update(d);
        }
        ctx.final(&mac);

        if (!std.mem.eql(u8, &mac, expected)) return error.Authenticity;
    }
};
