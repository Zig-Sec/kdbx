const std = @import("std");
const Allocator = std.mem.Allocator;

const misc = @import("../misc.zig");
const decode = misc.decode;
const encode2 = misc.encode2;

pub const InnerFieldTag = enum(u8) {
    end_of_header = 0,
    stream_cipher = 1,
    stream_key = 2,
    binary = 3,

    pub fn fromByte(b: u8) !@This() {
        return switch (b) {
            0 => .end_of_header,
            1 => .stream_cipher,
            2 => .stream_key,
            3 => .binary,
            else => error.UndefinedHeaderField,
        };
    }
};

pub const InnerHeader = struct {
    stream_cipher: StreamCipher,
    stream_key: []u8,
    binary: std.ArrayList([]u8),
    allocator: Allocator,

    pub const StreamCipher = enum(u32) {
        ArcFourVariant = 1,
        Salsa20 = 2,
        ChaCha20 = 3,

        pub fn fromSlice(s: []const u8) !@This() {
            if (s.len != 4) return error.InvalidSize;
            const v = decode(u32, s);
            return switch (v) {
                1 => .ArcFourVariant,
                2 => .Salsa20,
                3 => .ChaCha20,
                else => error.UnsupportedStreamCipher,
            };
        }
    };

    pub fn write(self: *const @This(), out: anytype) !void {
        try out.writeAll("\x01\x04\x00\x00\x00");
        try encode2(out, 4, @intFromEnum(self.stream_cipher));

        try out.writeByte(0x02);
        try encode2(out, 4, @as(u32, @intCast(self.stream_key.len)));
        try out.writeAll(self.stream_key);

        for (self.binary.items) |binary| {
            try out.writeByte(0x03);
            try encode2(out, 4, @as(u32, @intCast(binary.len + 1)));
            try out.writeByte(0x01); // protected flag even though we don't protect the data (same as KeePassXC).
            try out.writeAll(binary);
        }

        // End of Header
        //try out.writeByte(0x00);
        try out.writeAll("\x00\x00\x00\x00\x00");
    }

    pub fn readAlloc(s: []const u8, allocator: Allocator, i: *usize) !@This() {
        var stream_cipher: ?StreamCipher = null;
        var stream_key: ?[]u8 = null;
        errdefer if (stream_key) |sk| {
            std.crypto.utils.secureZero(u8, sk);
            allocator.free(sk);
        };
        var binary = std.ArrayList([]u8).init(allocator);
        for (binary.items) |e| {
            std.crypto.utils.secureZero(u8, e);
            allocator.free(e);
        }
        errdefer binary.deinit();

        while (i.* < s.len) {
            if (i.* + 5 >= s.len) break;

            const t = s[i.*];
            i.* += 1;
            var s_: [4]u8 = undefined;
            @memcpy(&s_, s[i.* .. i.* + 4]);
            const size = std.mem.readInt(u32, &s_, .little);
            i.* += 4;

            if (i.* + size >= s.len) break;
            const m = s[i.* .. i.* + size];
            i.* += size;

            switch (t) {
                0 => break, // EOF
                1 => stream_cipher = try StreamCipher.fromSlice(m),
                2 => stream_key = try allocator.dupe(u8, m),
                3 => {
                    if (m.len == 0) return error.InnerHeaderBinaryMissingFlag;
                    switch (m[0]) {
                        0 => {},
                        1 => {}, // "protected" but KeePassXC just sets it
                        else => {
                            std.log.err("InnerHeaderInvalidBinaryFlag {d}", .{m[0]});
                            return error.InnerHeaderInvalidBinaryFlag;
                        },
                    }
                    try binary.append(try allocator.dupe(u8, m[1..]));
                },
                else => {},
            }
        }

        if (stream_cipher == null) return error.StreamCipherMissing;
        if (stream_key == null) return error.StreamKeyMissing;

        switch (stream_cipher.?) {
            .ChaCha20 => if (stream_key.?.len != 64) return error.UnexpectedStreamKeyLength,
            else => return error.UnsupportedStreamCipher,
        }

        return @This(){
            .stream_cipher = stream_cipher.?,
            .stream_key = stream_key.?,
            .binary = binary,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *const @This()) void {
        std.crypto.utils.secureZero(u8, self.stream_key);
        self.allocator.free(self.stream_key);

        for (self.binary.items) |e| {
            std.crypto.utils.secureZero(u8, e);
            self.allocator.free(e);
        }
        self.binary.deinit();
    }
};
