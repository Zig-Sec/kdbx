const std = @import("std");
const Allocator = std.mem.Allocator;

const v4 = @import("../v4.zig");
const InnerHeader = v4.InnerHeader;
const Header = v4.Header;
const Keys = v4.Keys;
const XML = v4.XML;
const parseXml = v4.parseXml;

pub const Body = struct {
    inner_header: InnerHeader,
    xml: []u8,
    allocator: Allocator,

    pub fn readAlloc(
        reader: anytype,
        header: *const Header,
        keys: *const Keys,
        allocator: Allocator,
    ) !@This() {
        var inner = std.ArrayList(u8).init(allocator);
        defer inner.deinit();

        var i: u64 = 0;
        while (true) : (i += 1) {
            var mac: [32]u8 = .{0} ** 32;
            _ = reader.readAll(&mac) catch |e| {
                std.log.err("unable to read mac of block {d}", .{i});
                return e;
            };

            const len = reader.readInt(u32, .little) catch |e| {
                std.log.err("unable to read length of block {d}", .{i});
                return e;
            };

            const curr = inner.items.len;

            // TODO: make this more efficient
            for (0..len) |_| {
                try inner.append(try reader.readByte());
            }

            var raw_block_index: [8]u8 = undefined;
            std.mem.writeInt(u64, &raw_block_index, i, .little);
            var raw_block_len: [4]u8 = undefined;
            std.mem.writeInt(u32, &raw_block_len, len, .little);

            keys.checkMac(&mac, &.{ &raw_block_index, &raw_block_len, inner.items[curr..] }, i) catch |e| {
                std.log.err("unable to verify authenticity of block {d}", .{i});
                return e;
            };

            // Break if length is less than 1MiB
            if (len < 1048576) break;
        }

        const iv = header.getEncryptionIv();
        switch (header.getCipherId()) {
            .aes128_cbc, .twofish_cbc, .chacha20 => {
                return error.UnsupportedCipher;
            },
            .aes256_cbc => {
                var xor_vector: [16]u8 = undefined;
                var j: usize = 0;

                @memcpy(&xor_vector, iv[0..16]);
                var ctx = std.crypto.core.aes.Aes256.initDec(keys.ekey);

                while (j < inner.items.len) : (j += 16) {
                    var data: [16]u8 = .{0} ** 16;
                    const offset = if (j + 16 <= inner.items.len) 16 else inner.items.len - j;
                    var in_: [16]u8 = .{0} ** 16;
                    @memcpy(in_[0..offset], inner.items[j .. j + offset]);

                    ctx.decrypt(data[0..], &in_);
                    for (&data, xor_vector) |*b1, b2| {
                        b1.* ^= b2;
                    }

                    // This could be bad if a block is not divisible by 16 but
                    // this will only happen for the last block, i.e.,
                    // doesn't affect the CBC decryption.
                    @memcpy(xor_vector[0..offset], inner.items[j .. j + offset]);

                    @memcpy(inner.items[j .. j + offset], data[0..offset]);
                }
            },
        }

        switch (header.getCompression()) {
            .none => {},
            .gzip => {
                var in_stream = std.io.fixedBufferStream(inner.items);

                var decompressed = std.ArrayList(u8).init(allocator);
                errdefer decompressed.deinit();

                try std.compress.gzip.decompress(
                    in_stream.reader(),
                    decompressed.writer(),
                );

                inner.deinit();
                inner = decompressed;
            },
        }

        var k: usize = 0;
        const inner_header = try InnerHeader.readAlloc(
            inner.items,
            allocator,
            &k,
        );

        //std.debug.print("{s}\n", .{inner.items});

        return @This(){
            .inner_header = inner_header,
            .xml = try allocator.dupe(u8, inner.items[k..]),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *@This()) void {
        std.crypto.utils.secureZero(u8, self.xml);
        self.allocator.free(self.xml);

        self.inner_header.deinit();
    }

    pub fn getXml(self: *const @This(), allocator: Allocator) !XML {
        return try parseXml(self, allocator);
    }
};
