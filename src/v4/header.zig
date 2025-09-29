const std = @import("std");
const Allocator = std.mem.Allocator;

const misc = @import("../misc.zig");
const encode = misc.encode;
const encode2 = misc.encode2;
const decode = misc.decode;

const v4 = @import("../v4.zig");
const Field = v4.Field;
const Keys = v4.Keys;

const DatabaseKey = @import("../DatabaseKey.zig");

/// The version information of a KDBX database.
///
/// The first 12 bytes of every KDBX database contain its version information.
pub const HVersion = struct {
    raw: [12]u8,

    /// Create a new version header.
    pub fn new(s1: u32, s2: u32, vmin: u16, vmaj: u16) @This() {
        var tmp: @This() = undefined;
        @memcpy(tmp.raw[0..4], encode(4, s1)[0..]);
        @memcpy(tmp.raw[4..8], encode(4, s2)[0..]);
        @memcpy(tmp.raw[8..10], encode(2, vmin)[0..]);
        @memcpy(tmp.raw[10..12], encode(2, vmaj)[0..]);
        return tmp;
    }

    pub fn write(self: *const @This(), out: *std.Io.Writer) !void {
        try out.writeAll(self.raw[0..]);
    }

    pub fn @"versionSupported?"(self: *const @This(), versions: []const [2]u32) bool {
        for (versions) |version| {
            if (self.getSignature2() == version[0] and self.getMajorVersion() == version[1])
                return true;
        }
        return false;
    }

    /// Get the first signature. This is always 0x9AA2D903!
    pub fn getSignature1(self: *const @This()) u32 {
        return decode(u32, self.raw[0..4]);
    }

    pub fn setSignature1(self: *@This(), s: u32) void {
        @memcpy(self.raw[0..4], encode(4, s)[0..]);
    }

    /// Get the second signature. The signature depends on the version of the database.
    pub fn getSignature2(self: *const @This()) u32 {
        return decode(u32, self.raw[4..8]);
    }

    pub fn setSignature2(self: *@This(), s: u32) void {
        @memcpy(self.raw[4..8], encode(4, s)[0..]);
    }

    /// Get the minor version number, e.g. `1` for v4.1.
    pub fn getMinorVersion(self: *const @This()) u16 {
        return decode(u16, self.raw[8..10]);
    }

    pub fn setMinorVersion(self: *@This(), v: u16) void {
        @memcpy(self.raw[8..10], encode(2, v)[0..]);
    }

    /// Get the major version number, e.g. `4` for v4.1.
    pub fn getMajorVersion(self: *const @This()) u16 {
        return decode(u16, self.raw[10..12]);
    }

    pub fn setMajorVersion(self: *@This(), v: u16) void {
        @memcpy(self.raw[10..12], encode(2, v)[0..]);
    }
};

/// A KDBX4 Header.
pub const Header = struct {
    version: HVersion,
    fields: [6]?Field,
    raw_header: []const u8,
    hash: [32]u8,
    mac: [32]u8,
    allocator: Allocator,

    const supported_versions = &.{
        .{ 0xB54BFB67, 4 }, // signature and major version
    };

    // Call this before saving a database
    pub fn renewSecrets(self: *@This()) void {
        // Renew Encryption IV
        std.crypto.random.bytes(&self.fields[3].?);

        // Renew Main Seed
        std.crypto.random.bytes(&self.fields[2].?);

        // Renew Salt/Seed for KDF
        switch (self.fields[4].?) {
            .aes => |aes| std.crypto.random.bytes(&aes.s),
            .argon2 => |argon| std.crypto.random.bytes(&argon.s),
        }

        // yes, this is required by the "spec".
    }

    // Call this function after changing the version or one of the
    // header fields.
    pub fn updateRawHeader(self: *@This()) !void {
        var out = std.Io.Writer.Allocating.init(self.allocator);
        errdefer out.deinit();

        try self.version.write(&out.writer);

        for (self.fields[0..]) |field_| {
            if (field_) |field| {
                switch (field) {
                    .cipher_id => |id| {
                        try out.writer.writeAll("\x02\x10\x00\x00\x00");
                        try encode2(&out.writer, 16, id.toUint());
                    },
                    .compression => |comp| {
                        try out.writer.writeAll("\x03\x04\x00\x00\x00");
                        try encode2(&out.writer, 4, @intFromEnum(comp));
                    },
                    .main_seed => |seed| {
                        try out.writer.writeByte(0x04);
                        try encode2(&out.writer, 4, @as(u32, 32));
                        try out.writer.writeAll(seed[0..]);
                    },
                    .encryption_iv => |iv| {
                        try out.writer.writeByte(0x07);

                        switch (self.getCipherId()) {
                            .aes128_cbc, .aes256_cbc, .twofish_cbc => {
                                try encode2(&out.writer, 4, @as(u32, 16));
                                try out.writer.writeAll(iv[0..16]);
                            },
                            .chacha20 => {
                                try encode2(&out.writer, 4, @as(u32, 12));
                                try out.writer.writeAll(iv[0..12]);
                            },
                        }
                    },
                    .kdf_parameters => |params| {
                        try out.writer.writeByte(0x0b);

                        switch (params) {
                            .aes => return error.SerializingAesKdfParametersNotSupported,
                            .argon2 => |argon2| {
                                try out.writer.writeAll("\x8b\x00\x00\x00"); // this is always the same
                                try out.writer.writeAll("\x00\x01"); // version

                                // $UUID
                                try out.writer.writeByte(0x42);
                                try encode2(&out.writer, 4, @as(u32, 5));
                                try out.writer.writeAll("$UUID");
                                try encode2(&out.writer, 4, @as(u32, 16));
                                switch (argon2.mode) {
                                    .argon2d => try out.writer.writeAll("\xef\x63\x6d\xdf\x8c\x29\x44\x4b\x91\xf7\xa9\xa4\x03\xe3\x0a\x0c"),
                                    .argon2id => try out.writer.writeAll("\x9e\x29\x8b\x19\x56\xdb\x47\x73\xb2\x3d\xfc\x3e\xc6\xf0\xa1\xe6"),
                                    .argon2i => return error.KdfParamsArgon2iNotSupportedForSerialization,
                                }

                                // I
                                try out.writer.writeByte(0x05);
                                try encode2(&out.writer, 4, @as(u32, 1));
                                try out.writer.writeByte('I');
                                try encode2(&out.writer, 4, @as(u32, 8));
                                try encode2(&out.writer, 8, argon2.i);

                                // M
                                try out.writer.writeByte(0x05);
                                try encode2(&out.writer, 4, @as(u32, 1));
                                try out.writer.writeByte('M');
                                try encode2(&out.writer, 4, @as(u32, 8));
                                try encode2(&out.writer, 8, argon2.m);

                                // P
                                try out.writer.writeByte(0x04);
                                try encode2(&out.writer, 4, @as(u32, 1));
                                try out.writer.writeByte('P');
                                try encode2(&out.writer, 4, @as(u32, 4));
                                try encode2(&out.writer, 4, argon2.p);

                                // S
                                try out.writer.writeByte(0x42);
                                try encode2(&out.writer, 4, @as(u32, 1));
                                try out.writer.writeByte('S');
                                try encode2(&out.writer, 4, @as(u32, 32));
                                try out.writer.writeAll(argon2.s[0..]);

                                // V
                                try out.writer.writeByte(0x04);
                                try encode2(&out.writer, 4, @as(u32, 1));
                                try out.writer.writeByte('V');
                                try encode2(&out.writer, 4, @as(u32, 4));
                                try encode2(&out.writer, 4, argon2.v);

                                // TODO: do we need to care about k and a???
                            },
                        }

                        try out.writer.writeByte(0x00);
                    },
                    .public_custom_data => {
                        return error.SerializingPublicCustomDataNotSupported;
                    },
                    .end_of_header => {
                        // We serialize it extra (see below)...
                    },
                }
            }
        }

        // End of Heder
        try out.writer.writeAll("\x00\x04\x00\x00\x00\x0d\x0a\x0d\x0a");

        const raw_header = try out.toOwnedSlice();
        self.allocator.free(self.raw_header);
        self.raw_header = raw_header;
    }

    pub fn updateHash(self: *@This()) void {
        std.crypto.hash.sha2.Sha256.hash(self.raw_header, &self.hash, .{});
    }

    pub fn updateMac(self: *@This(), keys: *const Keys) void {
        self.mac = keys.calculateMac(
            &.{self.raw_header},
            0xffffffffffffffff,
        );
    }

    pub fn readAlloc(reader: *std.Io.Reader, allocator: Allocator) !@This() {
        var j: usize = 0;
        // Read and validate version
        var version: HVersion = undefined;
        _ = reader.readSliceAll(&version.raw) catch |e| {
            std.log.err("Header.read: error while reading version ({any})", .{e});
            return error.UnexpectedError;
        };
        j += 12;

        if (version.getSignature1() != 0x9AA2D903) {
            std.log.err("Header.read: error while reading version", .{});
            return error.InvalidSignature1;
        }

        if (!version.@"versionSupported?"(supported_versions)) {
            std.log.err("Header.read: version {d} is not supported", .{version.getMajorVersion()});
            return error.UnsupportedVersion;
        }

        // First read header as we have to verify its integrity
        var raw_header = std.Io.Writer.Allocating.init(allocator);
        errdefer raw_header.deinit();
        try raw_header.writer.writeAll(&version.raw);

        var count: usize = 0;
        var before: u8 = 0;
        while (true) {
            const byte = reader.takeByte() catch |e| {
                std.log.err("unable to read {d}'th byte for header ({any})", .{ count, e });
                return e;
            };
            try raw_header.writer.writeByte(byte);
            count += 1;

            if (before == 0x0d and byte == 0x0a and raw_header.written().len >= 9) {
                if (std.mem.eql(
                    u8,
                    "\x00\x04\x00\x00\x00\x0d\x0a\x0d\x0a",
                    raw_header.written()[raw_header.written().len - 9 ..],
                )) break;
            }

            before = byte;
        }

        var hash: [32]u8 = .{0} ** 32;
        _ = try reader.readSliceAll(&hash);

        var mac: [32]u8 = .{0} ** 32;
        _ = try reader.readSliceAll(&mac);

        var sha256_digest: [32]u8 = .{0} ** 32;
        std.crypto.hash.sha2.Sha256.hash(raw_header.written(), &sha256_digest, .{});
        if (!std.mem.eql(u8, &hash, &sha256_digest)) return error.Integrity;

        // Now parse the header fields
        var stream = std.Io.Reader.fixed(raw_header.written());
        const stream_reader = &stream;
        try stream_reader.discardAll(12); // skip version

        var fields_: [6]?Field = .{null} ** 6;
        errdefer {
            for (fields_[0..]) |field| {
                if (field) |f| f.deinit();
            }
        }

        // Parse fields
        for (0..7) |i| {
            _ = i;
            const f = Field.readAlloc(stream_reader, allocator, &j) catch |e| {
                return e;
            };
            switch (f) {
                .end_of_header => break,
                else => {},
            }
            fields_[f.getIndex().?] = f; // We already checked that f is not EOH
        }

        if (fields_[0] == null) return error.CipherIdMissing;
        if (fields_[1] == null) return error.CompressionMissing;
        if (fields_[2] == null) return error.MainSeedMissing;
        if (fields_[3] == null) return error.EncryptionIvMissing;
        if (fields_[4] == null) return error.KdfParametersMissing;
        // Public custom data might be missing... this is allowed

        return @This(){
            .version = version,
            .fields = fields_,
            .allocator = allocator,
            .raw_header = try raw_header.toOwnedSlice(),
            .hash = hash,
            .mac = mac,
        };
    }

    pub fn deinit(self: *const @This()) void {
        for (self.fields[0..]) |field| {
            if (field) |f| f.deinit();
        }
        self.allocator.free(self.raw_header);
    }

    pub fn getCipherId(self: *const @This()) Field.Cipher {
        return self.fields[0].?.cipher_id;
    }

    pub fn getCompression(self: *const @This()) Field.Compression {
        return self.fields[1].?.compression;
    }

    pub fn setCompression(self: *@This(), comp: Field.Compression) void {
        self.fields[1].?.compression = comp;
    }

    pub fn getMainSeed(self: *const @This()) Field.MainSeed {
        return self.fields[2].?.main_seed;
    }

    pub fn getEncryptionIv(self: *const @This()) Field.Iv {
        return self.fields[3].?.encryption_iv;
    }

    pub fn getKdfParameters(self: *const @This()) Field.KdfParameters {
        return self.fields[4].?.kdf_parameters;
    }

    /// Derive the encryption and mac key.
    pub fn deriveKeys(
        self: *const @This(),
        database_key: DatabaseKey,
    ) !Keys {
        // Create composite key
        var composite_key: [32]u8 = .{0} ** 32;
        defer std.crypto.secureZero(u8, &composite_key);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        if (database_key.password) |password| {
            var pwhash: [32]u8 = .{0} ** 32;
            defer std.crypto.secureZero(u8, &pwhash);
            std.crypto.hash.sha2.Sha256.hash(password, &pwhash, .{});
            h.update(&pwhash);
        }
        if (database_key.keyfile) |kf| h.update(kf);
        if (database_key.keyprovider) |kp| h.update(kp);
        h.final(&composite_key);

        // Generate pre-key
        var pre_key: [32]u8 = .{0} ** 32;
        defer std.crypto.secureZero(u8, &pre_key);
        switch (self.getKdfParameters()) {
            .aes => {
                return error.AesKdfNotImplemented;
            },
            .argon2 => |kdf| {
                try std.crypto.pwhash.argon2.kdf(
                    self.allocator,
                    &pre_key,
                    &composite_key,
                    &kdf.s,
                    .{
                        .t = @intCast(kdf.i),
                        .m = @intCast(kdf.m / 1024), // has to be provided in KiB
                        .p = @intCast(kdf.p),
                        .secret = kdf.k,
                        .ad = kdf.a,
                    },
                    kdf.mode,
                );
            },
        }

        const main_seed = self.getMainSeed();

        // Derive encryption key
        var encryption_key: [32]u8 = .{0} ** 32;
        defer std.crypto.secureZero(u8, &encryption_key);
        h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(&main_seed);
        h.update(&pre_key);
        h.final(&encryption_key);

        // Derive master-mac key
        var mac_key: [64]u8 = .{0} ** 64;
        defer std.crypto.secureZero(u8, &mac_key);
        var h2 = std.crypto.hash.sha2.Sha512.init(.{});
        h2.update(&main_seed);
        h2.update(&pre_key);
        h2.update("\x01");
        h2.final(&mac_key);

        return Keys{
            .ekey = encryption_key,
            .mkey = mac_key,
        };
    }

    pub fn checkMac(self: *const @This(), keys: *const Keys) !void {
        try keys.checkMac(
            &self.mac,
            &.{self.raw_header},
            0xffffffffffffffff,
        );
    }
};
