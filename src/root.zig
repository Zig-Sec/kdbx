const std = @import("std");
const dishwasher = @import("dishwasher");
const Uuid = @import("uuid");
const ChaCha20 = @import("chacha.zig").ChaCha20;
const xml = @import("xml.zig");

const Allocator = std.mem.Allocator;

// Why not just use fucking EPOCH
const TIME_DIFF_KDBX_EPOCH_IN_SEC = 62135600008;

const XML_INDENT = 2;

// +--------------------------------------------------+
// |Header: Unencrypted                               |
// +--------------------------------------------------+

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

    pub fn readAlloc(reader: anytype, allocator: Allocator) !@This() {
        var j: usize = 0;
        // Read and validate version
        var version: HVersion = undefined;
        _ = reader.readAll(&version.raw) catch |e| {
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
        var raw_header = std.ArrayList(u8).init(allocator);
        errdefer raw_header.deinit();
        try raw_header.appendSlice(&version.raw);

        var before: u8 = 0;
        while (true) {
            const byte = try reader.readByte();
            try raw_header.append(byte);

            if (before == 0x0d and byte == 0x0a and raw_header.items.len >= 9) {
                if (std.mem.eql(
                    u8,
                    "\x00\x04\x00\x00\x00\x0d\x0a\x0d\x0a",
                    raw_header.items[raw_header.items.len - 9 ..],
                )) break;
            }

            before = byte;
        }

        var hash: [32]u8 = .{0} ** 32;
        _ = try reader.readAll(&hash);

        var mac: [32]u8 = .{0} ** 32;
        _ = try reader.readAll(&mac);

        var sha256_digest: [32]u8 = .{0} ** 32;
        std.crypto.hash.sha2.Sha256.hash(raw_header.items, &sha256_digest, .{});
        if (!std.mem.eql(u8, &hash, &sha256_digest)) return error.Integrity;

        // Now parse the header fields
        var stream = std.io.fixedBufferStream(raw_header.items);
        const stream_reader = stream.reader();
        try stream_reader.skipBytes(12, .{}); // skip version

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
        pw: ?[]const u8,
        keyfile: ?[]const u8,
        keyprovider: ?[]const u8,
    ) !Keys {
        // Create composite key
        var composite_key: [32]u8 = .{0} ** 32;
        defer std.crypto.utils.secureZero(u8, &composite_key);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        if (pw) |password| {
            var pwhash: [32]u8 = .{0} ** 32;
            defer std.crypto.utils.secureZero(u8, &pwhash);
            std.crypto.hash.sha2.Sha256.hash(password, &pwhash, .{});
            h.update(&pwhash);
        }
        if (keyfile) |kf| h.update(kf);
        if (keyprovider) |kp| h.update(kp);
        h.final(&composite_key);

        // Generate pre-key
        var pre_key: [32]u8 = .{0} ** 32;
        defer std.crypto.utils.secureZero(u8, &pre_key);
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
        defer std.crypto.utils.secureZero(u8, &encryption_key);
        h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(&main_seed);
        h.update(&pre_key);
        h.final(&encryption_key);

        // Derive master-mac key
        var mac_key: [64]u8 = .{0} ** 64;
        defer std.crypto.utils.secureZero(u8, &mac_key);
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

// # Body
// ####################################################

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
                    var in_: [16]u8 = undefined;
                    @memcpy(in_[0..offset], inner.items[j .. j + offset]);

                    ctx.decrypt(data[0..], &in_);
                    for (&data, xor_vector) |*b1, b2| {
                        b1.* ^= b2;
                    }

                    // This could be bad if a block is not divisible by 16 but
                    // this will only happen for the last block, i.e.,
                    // doesn't affect the CBC decryption.
                    @memcpy(&xor_vector, inner.items[j .. j + offset]);

                    @memcpy(inner.items[j .. j + offset], data[0..]);
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
        return try xml.parseXml(self, allocator);
    }
};

// # XML
// ####################################################

pub const XML = struct {
    meta: Meta,
    root: Group,

    pub fn deinit(self: *const @This()) void {
        self.meta.deinit();
        self.root.deinit();
    }
};

pub const Meta = struct {
    generator: []u8,
    database_name: []u8,
    database_name_changed: i64,
    database_description: ?[]u8 = null,
    database_description_changed: i64,
    default_user_name: ?[]u8 = null,
    default_user_name_changed: i64,
    maintenance_history_days: i64,
    color: ?[]u8 = null,
    master_key_changed: i64,
    master_key_change_rec: i64,
    master_key_change_force: i64,
    memory_protection: struct {
        protect_title: bool,
        protect_user_name: bool,
        protect_password: bool,
        protect_url: bool,
        protect_notes: bool,
    },
    custom_icons: ?std.ArrayList(Icon) = null,
    recycle_bin_enabled: bool,
    recycle_bin_uuid: Uuid.Uuid,
    recycle_bin_changed: i64,
    entry_template_group: Uuid.Uuid,
    entry_template_group_changed: i64,
    last_selected_group: Uuid.Uuid,
    last_top_visible_group: Uuid.Uuid,
    history_max_items: i64,
    history_max_size: i64,
    settings_changed: i64,
    custom_data: std.ArrayList(KeyValue),
    allocator: Allocator,

    pub fn deinit(self: *const @This()) void {
        std.crypto.utils.secureZero(u8, self.generator);
        self.allocator.free(self.generator);

        std.crypto.utils.secureZero(u8, self.database_name);
        self.allocator.free(self.database_name);

        if (self.database_description) |desc| {
            std.crypto.utils.secureZero(u8, desc);
            self.allocator.free(desc);
        }

        if (self.default_user_name) |desc| {
            std.crypto.utils.secureZero(u8, desc);
            self.allocator.free(desc);
        }

        if (self.color) |desc| {
            std.crypto.utils.secureZero(u8, desc);
            self.allocator.free(desc);
        }

        if (self.custom_icons) |icon| {
            for (icon.items) |data| data.deinit(self.allocator);
            icon.deinit();
        }

        for (self.custom_data.items) |data| data.deinit(self.allocator);
        self.custom_data.deinit();
    }
};

pub const Icon = struct {
    uuid: Uuid.Uuid,
    last_modification_time: i64,
    data: []u8,

    pub fn deinit(self: *const @This(), allocator: Allocator) void {
        std.crypto.utils.secureZero(u8, self.data);
        allocator.free(self.data);
    }
};

pub const KeyValue = struct {
    key: []u8,
    value: []u8,
    protected: bool = false,

    pub fn deinit(self: *const @This(), allocator: Allocator) void {
        std.crypto.utils.secureZero(u8, self.key);
        std.crypto.utils.secureZero(u8, self.value);
        allocator.free(self.key);
        allocator.free(self.value);
    }

    pub fn toXml(
        self: *const @This(),
        out: anytype,
        level: usize,
        allocator: Allocator,
        cipher: *ChaCha20,
    ) !void {
        for (0..level * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<String>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<Key>");
        try out.writeAll(self.key);
        try out.writeAll("</Key>\n");

        if (self.value.len > 0) {
            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            if (self.protected) {
                try out.writeAll("<Value Protected=\"True\">");
                const m = try allocator.dupe(u8, self.value);
                defer {
                    std.crypto.utils.secureZero(u8, m);
                    allocator.free(m);
                }
                cipher.xor(m);
                try xml.writeBase64(out, m, allocator);
            } else {
                try out.writeAll("<Value>");
                try out.print("{s}", .{self.value});
            }
            try out.writeAll("</Value>\n");
        } else {
            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("<Value/>\n");
        }

        for (0..level * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("</String>\n");
    }
};

pub const Group = struct {
    uuid: Uuid.Uuid,
    name: []u8,
    notes: ?[]u8 = null,
    icon_id: i64,
    times: Times,
    is_expanded: bool = false,
    default_auto_type_sequence: ?[]u8 = null,
    enable_auto_type: ?bool = null,
    enable_searching: ?bool = null,
    last_top_visible_entry: Uuid.Uuid,
    previous_parent_group: ?Uuid.Uuid = null,
    entries: std.ArrayList(Entry),
    groups: std.ArrayList(Group),
    allocator: Allocator,

    pub fn toXml(
        self: *const @This(),
        out: anytype,
        level: usize,
        cipher: *ChaCha20,
    ) !void {
        for (0..level * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<Group>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<UUID>");
        try xml.writeUuid(out, self.uuid, self.allocator);
        try out.writeAll("</UUID>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<Name>");
        try out.writeAll(self.name);
        try out.writeAll("</Name>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        if (self.notes) |notes| {
            try out.writeAll("<Notes>");
            try out.writeAll(notes);
            try out.writeAll("</Notes>\n");
        } else {
            try out.writeAll("<Notes/>\n");
        }

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<IconID>");
        try out.print("{d}", .{self.icon_id});
        try out.writeAll("</IconID>\n");

        try self.times.toXml(out, level + 1, self.allocator);

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<IsExpanded>");
        try out.print("{s}", .{if (self.is_expanded) "True" else "False"});
        try out.writeAll("</IsExpanded>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        if (self.default_auto_type_sequence) |seq| {
            try out.writeAll("<DefaultAutoTypeSequence>");
            try out.writeAll(seq);
            try out.writeAll("</DefaultAutoTypeSequence>\n");
        } else {
            try out.writeAll("<DefaultAutoTypeSequence/>\n");
        }

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        if (self.enable_auto_type) |t| {
            try out.writeAll("<EnableAutoType>");
            try out.print("{s}", .{if (t) "True" else "False"});
            try out.writeAll("</EnableAutoType>\n");
        } else {
            try out.writeAll("<EnableAutoType>null</EnableAutoType>\n");
        }

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        if (self.enable_searching) |t| {
            try out.writeAll("<EnableSearching>");
            try out.print("{s}", .{if (t) "True" else "False"});
            try out.writeAll("</EnableSearching>\n");
        } else {
            try out.writeAll("<EnableSearching>null</EnableSearching>\n");
        }

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<LastTopVisibleEntry>");
        try xml.writeUuid(
            out,
            self.last_top_visible_entry,
            self.allocator,
        );
        try out.writeAll("</LastTopVisibleEntry>\n");

        if (self.previous_parent_group) |ppg| {
            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("<PreviousParentGroup>");
            try xml.writeUuid(
                out,
                ppg,
                self.allocator,
            );
            try out.writeAll("</PreviousParentGroup>\n");
        }

        for (self.entries.items) |entry| {
            try entry.toXml(out, level + 1, cipher);
        }

        for (self.groups.items) |group| {
            try group.toXml(out, level + 1, cipher);
        }

        for (0..level * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("</Group>\n");
    }

    pub fn deinit(self: *const @This()) void {
        std.crypto.utils.secureZero(u8, self.name);
        self.allocator.free(self.name);

        if (self.notes) |v| {
            std.crypto.utils.secureZero(u8, v);
            self.allocator.free(v);
        }

        if (self.default_auto_type_sequence) |v| {
            std.crypto.utils.secureZero(u8, v);
            self.allocator.free(v);
        }

        for (self.entries.items) |e| {
            e.deinit();
        }
        self.entries.deinit();

        for (self.groups.items) |g| {
            g.deinit();
        }
        self.groups.deinit();
    }
};

pub const Entry = struct {
    uuid: Uuid.Uuid,
    icon_id: i64,
    custom_icon_uuid: ?Uuid.Uuid = null,
    foreground_color: ?[]u8 = null,
    background_color: ?[]u8 = null,
    override_url: ?[]u8 = null,
    tags: ?[]u8 = null,
    times: Times,
    strings: std.ArrayList(KeyValue),
    // TODO: Binary
    auto_type: ?AutoType = null,
    history: ?std.ArrayList(Entry) = null,
    allocator: Allocator,

    pub fn get(self: *const @This(), key: []const u8) ?[]u8 {
        for (self.strings.items) |kv| {
            if (std.mem.eql(u8, key, kv.key)) return kv.value;
        }
        return null;
    }

    pub fn set(self: *@This(), key: []const u8, value: []const u8, protect: bool) !void {
        self.times.last_access_time = std.time.timestamp() + TIME_DIFF_KDBX_EPOCH_IN_SEC;
        self.times.last_modification_time = self.times.last_access_time;

        for (self.strings.items) |*kv| {
            if (std.mem.eql(u8, key, kv.*.key)) {
                const m = try self.allocator.dupe(u8, value);
                self.allocator.free(kv.*.value);
                kv.*.value = m;
                return;
            }
        }

        const k = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(k);
        const v = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(v);

        try self.strings.append(.{ .key = k, .value = v, .protected = protect });
    }

    pub fn toXml(
        self: *const @This(),
        out: anytype,
        level: usize,
        cipher: *ChaCha20,
    ) !void {
        for (0..level * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<Entry>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<UUID>");
        try xml.writeUuid(out, self.uuid, self.allocator);
        try out.writeAll("</UUID>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<IconID>");
        try out.print("{d}", .{self.icon_id});
        try out.writeAll("</IconID>\n");

        // TODO
        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<ForegroundColor/>\n");

        // TODO
        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<BackgroundColor/>\n");

        // TODO
        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<OverrideURL/>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        if (self.tags != null and self.tags.?.len > 0) {
            try out.writeAll("<Tags>");
            try out.writeAll(self.tags.?);
            try out.writeAll("</Tags>\n");
        } else {
            try out.writeAll("<Tags/>\n");
        }

        try self.times.toXml(out, level + 1, self.allocator);

        for (self.strings.items) |kv| {
            try kv.toXml(
                out,
                level + 1,
                self.allocator,
                cipher,
            );
        }

        if (self.auto_type) |at| {
            try at.toXml(out, level + 1, self.allocator);
        } else {
            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("<AutoType/>\n");
        }

        if (self.history) |hist| {
            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("<History>\n");

            for (hist.items) |entry| {
                try entry.toXml(out, level + 2, cipher);
            }

            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("</History>\n");
        } else {
            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("<History/>\n");
        }

        for (0..level * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("</Entry>\n");
    }

    pub fn deinit(self: *const @This()) void {
        if (self.foreground_color) |v| {
            std.crypto.utils.secureZero(u8, v);
            self.allocator.free(v);
        }
        if (self.background_color) |v| {
            std.crypto.utils.secureZero(u8, v);
            self.allocator.free(v);
        }
        if (self.override_url) |v| {
            std.crypto.utils.secureZero(u8, v);
            self.allocator.free(v);
        }
        if (self.tags) |v| {
            std.crypto.utils.secureZero(u8, v);
            self.allocator.free(v);
        }
        for (self.strings.items) |kv| {
            kv.deinit(self.allocator);
        }
        self.strings.deinit();
        if (self.auto_type) |v| v.deinit(self.allocator);

        if (self.history) |h| {
            for (h.items) |kv| {
                kv.deinit();
            }
            h.deinit();
        }
    }
};

pub const Times = struct {
    last_modification_time: i64,
    creation_time: i64,
    last_access_time: i64,
    expiry_time: i64,
    expires: bool,
    usage_count: i64,
    location_changed: i64,

    pub fn toXml(
        self: *const @This(),
        out: anytype,
        level: usize,
        allocator: Allocator,
    ) !void {
        for (0..level * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<Times>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<LastModificationTime>");
        try xml.writeI64(out, self.last_modification_time, allocator);
        try out.writeAll("</LastModificationTime>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<CreationTime>");
        try xml.writeI64(out, self.creation_time, allocator);
        try out.writeAll("</CreationTime>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<LastAccessTime>");
        try xml.writeI64(out, self.last_access_time, allocator);
        try out.writeAll("</LastAccessTime>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<ExpiryTime>");
        try xml.writeI64(out, self.expiry_time, allocator);
        try out.writeAll("</ExpiryTime>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<Expires>");
        try xml.writeBool(out, self.expires);
        try out.writeAll("</Expires>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<UsageCount>");
        try out.print("{d}", .{self.usage_count});
        try out.writeAll("</UsageCount>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<LocationChanged>");
        try xml.writeI64(out, self.location_changed, allocator);
        try out.writeAll("</LocationChanged>\n");

        for (0..level * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("</Times>\n");
    }
};

pub const AutoType = struct {
    enabled: bool = false,
    data_transfer_obfuscation: i64 = 0,
    default_sequence: ?[]u8 = null,

    pub fn deinit(self: *const @This(), allocator: Allocator) void {
        if (self.default_sequence) |s| allocator.free(s);
    }

    pub fn toXml(
        self: *const @This(),
        out: anytype,
        level: usize,
        allocator: Allocator,
    ) !void {
        _ = allocator;

        for (0..level * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<AutoType>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<Enabled>");
        try xml.writeBool(out, self.enabled);
        try out.writeAll("</Enabled>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<DataTransferObfuscation>");
        try out.print("{d}", .{self.data_transfer_obfuscation});
        try out.writeAll("</DataTransferObfuscation>\n");

        // TODO: Figure out what a DefaultSequence looks like
        //       and serialize it correctly.
        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<DefaultSequence/>\n");

        for (0..level * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("</AutoType>\n");
    }
};

// # Version
// ####################################################

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

// # Fields
// ####################################################

/// Tags for the Field union.
///
/// Except for `public_custom_data` all field types are expected to be present in a KDBX4
/// (outer) header exactly once.
pub const FieldTag = enum(u8) {
    end_of_header = 0,
    cipher_id = 2,
    compression = 3,
    main_seed = 4,
    encryption_iv = 7,
    kdf_parameters = 11,
    public_custom_data = 12,

    pub fn total() usize {
        return 7;
    }
};

/// The fields of a KDBX4 header.
pub const Field = union(FieldTag) {
    end_of_header: struct {},
    cipher_id: Cipher,
    compression: Compression,
    main_seed: MainSeed,
    encryption_iv: Iv,
    kdf_parameters: KdfParameters,
    public_custom_data: struct {
        fields: []const VField,
        allocator: Allocator,

        pub fn deinit(self: *const @This()) void {
            for (self.fields) |field| {
                field.deinit(self.allocator);
            }
            self.allocator.free(self.fields);
        }
    },

    /// KDBX4 supports four different ciphers:
    ///
    /// - AES128-CBC
    /// - AES256-CBC
    /// - TWOFISH-CBC
    /// - ChaCha20
    ///
    /// Please note that it is ChaCha20 and NOT XChaCha20 (the nonce
    /// extended version), i.e., don't generate the IV at random!
    pub const Cipher = enum(u128) {
        aes128_cbc = 0x35DDF83D563A748DC3416494A105AB61,
        aes256_cbc = 0xFF5AFC6A210558BE504371BFE6F2C131,
        twofish_cbc = 0x6C3465F97AD46AA3B94B6F579FF268AD,
        chacha20 = 0x9AB5DB319A3324A5B54C6F8B2B8A03D6,

        pub fn fromSlice(s: []const u8) !@This() {
            if (s.len != 16) return error.InvalidSize;
            const v = decode(u128, s);
            return switch (v) {
                0x35DDF83D563A748DC3416494A105AB61 => .aes128_cbc,
                0xFF5AFC6A210558BE504371BFE6F2C131 => .aes256_cbc,
                0x6C3465F97AD46AA3B94B6F579FF268AD => .twofish_cbc,
                0x9AB5DB319A3324A5B54C6F8B2B8A03D6 => .chacha20,
                else => error.UnsupportedCipher,
            };
        }
    };

    /// The supported compression modes.
    ///
    /// Compression is done before encryption. The only supported
    /// compression algorithm is Gzip.
    pub const Compression = enum(u32) {
        none = 0,
        gzip = 1,

        pub fn fromSlice(s: []const u8) !@This() {
            if (s.len != 4) return error.InvalidSize;
            const v = decode(u32, s);
            return switch (v) {
                0 => .none,
                1 => .gzip,
                else => error.UnsupportedCompression,
            };
        }
    };

    pub const MainSeed = [32]u8;

    pub const KdfTag = enum {
        aes,
        argon2,
    };

    /// KDBX4 supports two types KDFs:
    ///
    /// - AES-KDF
    /// - Argon2d/id
    ///
    /// Please ignore AES-KDF and just use Argon2id for new databases!
    pub const Kdf = enum(u128) {
        aes_kdf = 0xea4f8ac1080d74bf60448a629af3d9c9,
        argon2d = 0x0c0ae303a4a9f7914b44298cdf6d63ef,
        argon2id = 0xe6a1f0c63efc3db27347db56198b299e,
    };

    pub const KdfParameters = union(KdfTag) {
        aes: struct {
            /// Number of rounds
            r: u64,
            /// A random seeed
            s: [32]u8,
        },
        argon2: struct {
            /// A random salt
            s: [32]u8,
            /// Parallelism
            p: u32,
            /// Memory usage in bytes
            m: u64,
            /// Iterations
            i: u64,
            /// Argon2 version (either 0x10 or 0x13)
            v: u32,
            /// Optional key
            k: ?[]const u8 = null,
            /// Optional associated data
            a: ?[]const u8 = null,
            mode: std.crypto.pwhash.argon2.Mode,
            allocator: Allocator,

            pub fn deinit(self: *const @This()) void {
                if (self.k) |k| {
                    self.allocator.free(k);
                }
                if (self.a) |a| {
                    self.allocator.free(a);
                }
            }
        },
    };

    pub const Iv = [16]u8;

    /// Index function for the header. The indices are in no particular order.
    pub fn getIndex(self: *const @This()) ?usize {
        return switch (self.*) {
            .cipher_id => 0,
            .compression => 1,
            .main_seed => 2,
            .encryption_iv => 3,
            .kdf_parameters => 4,
            .public_custom_data => 5,
            .end_of_header => null,
        };
    }

    /// Read a Field from a `Reader`.
    pub fn readAlloc(reader: anytype, allocator: Allocator, j: *usize) !@This() {
        const t = try reader.readByte();
        j.* += 1;
        const size: usize = @intCast(try reader.readInt(u32, .little));
        j.* += 4;
        var m = try allocator.alloc(u8, size);
        for (m) |*b| b.* = try reader.readByte();
        //const m = try reader.readAllAlloc(allocator, size);
        defer allocator.free(m);
        j.* += m.len;
        if (m.len != size) return error.UnexpectedLength;

        return switch (t) {
            0 => Field{ .end_of_header = .{} },
            2 => Field{ .cipher_id = try Cipher.fromSlice(m) },
            3 => Field{ .compression = try Compression.fromSlice(m) },
            4 => blk: {
                if (m.len != 32) break :blk error.InvalidSize;
                break :blk Field{ .main_seed = m[0..32].* };
            },
            7 => blk: {
                if (m.len > 16) break :blk error.InvalidSize;
                // The acutal length is determined by the cipher. If aes is
                // used it is 16, otherwise (for chacha20) it is 12.
                var iv: [16]u8 = .{0} ** 16;
                @memcpy(iv[0..m.len], m);
                break :blk Field{ .encryption_iv = iv };
            },
            11 => blk: {
                var n: usize = 0;

                if (m.len < 2) return error.InvalidLength;
                const format = decode(u16, m[n .. n + 2]);
                if (format & 0xff00 != 0x100) break :blk error.InvalidVariantMapFormat;
                n += 2;

                var kdf_: ?Kdf = null;
                var r_: ?u64 = null;
                var s_: ?[32]u8 = null;
                var p_: ?u32 = null;
                var m_: ?u64 = null;
                var i_: ?u64 = null;
                var v_: ?u32 = null;
                var k_: ?[]const u8 = null;
                var a_: ?[]const u8 = null;

                while (n < m.len) {
                    if (m[n] == 0) break; // EOF

                    const vt = m[n];
                    n += 1;

                    if (n + 4 >= m.len) return error.InvalidLength;
                    var s: usize = @intCast(decode(u16, m[n .. n + 4]));
                    n += 4;

                    if (n + s >= m.len) return error.InvalidLength;
                    const k = m[n .. n + s];
                    n += s;

                    if (n + 4 >= m.len) return error.InvalidLength;
                    s = @intCast(decode(u16, m[n .. n + 4]));
                    n += 4;

                    if (n + s >= m.len) return error.InvalidLength;
                    const v = m[n .. n + s];
                    n += s;

                    const vf = VField{
                        .type = try VField.Type.fromByte(vt),
                        .key = k,
                        .value = v,
                    };

                    if (std.mem.eql(u8, vf.key, "R")) {
                        r_ = vf.getUInt64();
                    } else if (std.mem.eql(u8, vf.key, "S")) {
                        const b_ = vf.getByte();
                        if (b_ == null or b_.?.len != 32) return error.AesKdfSeed;
                        s_ = b_.?[0..32].*;
                    } else if (std.mem.eql(u8, vf.key, "$UUID")) {
                        if (vf.value.len != 16) return error.InvalidUuidLength;
                        const uuid = decode(u128, vf.value);
                        switch (uuid) {
                            0xea4f8ac1080d74bf60448a629af3d9c9 => kdf_ = .aes_kdf,
                            0x0c0ae303a4a9f7914b44298cdf6d63ef => kdf_ = .argon2d,
                            0xe6a1f0c63efc3db27347db56198b299e => kdf_ = .argon2id,
                            else => {},
                        }
                    } else if (std.mem.eql(u8, vf.key, "P")) {
                        p_ = vf.getUInt32();
                    } else if (std.mem.eql(u8, vf.key, "M")) {
                        m_ = vf.getUInt64();
                    } else if (std.mem.eql(u8, vf.key, "I")) {
                        i_ = vf.getUInt64();
                    } else if (std.mem.eql(u8, vf.key, "V")) {
                        v_ = vf.getUInt32();
                    } else if (std.mem.eql(u8, vf.key, "K")) {
                        k_ = vf.getByte();
                    } else if (std.mem.eql(u8, vf.key, "A")) {
                        a_ = vf.getByte();
                    }
                }

                if (kdf_ == null) return error.KdfUuidMissing;
                switch (kdf_.?) {
                    .aes_kdf => {
                        if (r_ == null) break :blk error.KdfRMissing;
                        if (s_ == null) break :blk error.KdfSMissing;
                        break :blk Field{
                            .kdf_parameters = .{ .aes = .{
                                .r = r_.?,
                                .s = s_.?[0..32].*,
                            } },
                        };
                    },
                    .argon2d, .argon2id => {
                        if (s_ == null) break :blk error.KdfSMissing;
                        if (p_ == null) break :blk error.KdfPMissing;
                        if (m_ == null) break :blk error.KdfMMissing;
                        if (i_ == null) break :blk error.KdfIMissing;
                        if (v_ == null) break :blk error.KdfVMissing;
                        var a = Field{
                            .kdf_parameters = .{ .argon2 = .{
                                .s = s_.?[0..32].*,
                                .p = p_.?,
                                .m = m_.?,
                                .i = i_.?,
                                .v = v_.?,
                                .mode = switch (kdf_.?) {
                                    .argon2d => .argon2d,
                                    else => .argon2id,
                                },
                                .allocator = allocator,
                            } },
                        };
                        errdefer {
                            if (a.kdf_parameters.argon2.k) |k__| allocator.free(k__);
                            if (a.kdf_parameters.argon2.a) |a__| allocator.free(a__);
                        }

                        if (k_) |k__| a.kdf_parameters.argon2.k =
                            try allocator.dupe(u8, k__);
                        if (a_) |a__| a.kdf_parameters.argon2.k =
                            try allocator.dupe(u8, a__);

                        break :blk a;
                    },
                }
            },
            else => error.InvalidHeaderField,
        };
    }

    pub fn deinit(self: *const @This()) void {
        switch (self.*) {
            .kdf_parameters => |kdf| {
                switch (kdf) {
                    .argon2 => |argon| {
                        argon.deinit();
                    },
                    else => {},
                }
            },
            .public_custom_data => |pcd| {
                pcd.deinit();
            },
            else => {},
        }
    }
};

pub const VField = struct {
    type: Type,
    key: []const u8,
    value: []const u8,

    pub const Type = enum(u8) {
        UInt32 = 0x04,
        UInt64 = 0x05,
        Bool = 0x08,
        Int32 = 0x0c,
        Int64 = 0x0d,
        String = 0x18,
        Byte = 0x42,

        pub fn fromByte(b: u8) !@This() {
            return switch (b) {
                0x04 => .UInt32,
                0x05 => .UInt64,
                0x08 => .Bool,
                0x0c => .Int32,
                0x0d => .Int64,
                0x18 => .String,
                0x42 => .Byte,
                else => error.InvalidVFieldType,
            };
        }
    };

    pub fn deinit(self: *const @This(), allocator: Allocator) void {
        allocator.free(self.key);
        allocator.free(self.value);
    }

    pub fn getUInt32(self: *const @This()) ?u32 {
        if (self.type != .UInt32) return null;
        if (self.value.len != 4) return null;
        return decode(u32, self.value);
    }

    pub fn getUInt64(self: *const @This()) ?u64 {
        if (self.type != .UInt64) return null;
        if (self.value.len != 8) return null;
        return decode(u64, self.value);
    }

    pub fn getBool(self: *const @This()) ?bool {
        if (self.type != .Bool) return null;
        if (self.value.len != 1) return null;
        return self.value[0] != 0;
    }

    pub fn getInt32(self: *const @This()) ?i32 {
        if (self.type != .Int32) return null;
        if (self.value.len != 4) return null;
        return decode(i32, self.value);
    }

    pub fn getInt64(self: *const @This()) ?i64 {
        if (self.type != .Int64) return null;
        if (self.value.len != 8) return null;
        return decode(i64, self.value);
    }

    pub fn getString(self: *const @This()) ?[]const u8 {
        if (self.type != .String) return null;
        return self.value;
    }

    pub fn getByte(self: *const @This()) ?[]const u8 {
        if (self.type != .Byte) return null;
        return self.value;
    }
};

// # Inner Header
// ####################################################

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
                3 => try binary.append(try allocator.dupe(u8, m)),
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

// +--------------------------------------------------+
// |Misc                                              |
// +--------------------------------------------------+

fn encode(comptime n: usize, int: anytype) [n]u8 {
    var tmp: [n]u8 = undefined;

    inline for (0..n) |i| {
        tmp[i] = @intCast((int >> (@as(u5, @intCast(i)) * 8)) & 0xff);
    }

    return tmp;
}

fn decode(T: type, arr: anytype) T {
    const bytes = @typeInfo(T).Int.bits / 8;
    var tmp: T = 0;

    for (0..bytes) |i| {
        tmp <<= 8;
        tmp += arr[bytes - (i + 1)];
    }

    return tmp;
}

// +--------------------------------------------------+
// |Tests                                             |
// +--------------------------------------------------+

test "HVersion #1" {
    var v = HVersion.new(0x9AA2D903, 0xB54BFB67, 1, 4);

    try std.testing.expectEqualSlices(u8, "\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x01\x00\x04\x00", &v.raw);
    try std.testing.expectEqual(@as(u32, 0x9AA2D903), v.getSignature1());
    try std.testing.expectEqual(@as(u32, 0xB54BFB67), v.getSignature2());
    try std.testing.expectEqual(@as(u16, 1), v.getMinorVersion());
    try std.testing.expectEqual(@as(u16, 4), v.getMajorVersion());

    v.setSignature2(0xcafebabe);
    v.setMinorVersion(3);
    v.setMajorVersion(5);
    try std.testing.expectEqual(@as(u32, 0xcafebabe), v.getSignature2());
    try std.testing.expectEqual(@as(u16, 3), v.getMinorVersion());
    try std.testing.expectEqual(@as(u16, 5), v.getMajorVersion());
}

test "decode outer header" {
    const s = "\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x01\x00\x04\x00\x02\x10\x00\x00\x00\x31\xc1\xf2\xe6\xbf\x71\x43\x50\xbe\x58\x05\x21\x6a\xfc\x5a\xff\x03\x04\x00\x00\x00\x01\x00\x00\x00\x04\x20\x00\x00\x00\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x07\x10\x00\x00\x00\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x0b\x8b\x00\x00\x00\x00\x01\x42\x05\x00\x00\x00\x24\x55\x55\x49\x44\x10\x00\x00\x00\xef\x63\x6d\xdf\x8c\x29\x44\x4b\x91\xf7\xa9\xa4\x03\xe3\x0a\x0c\x05\x01\x00\x00\x00\x49\x08\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x05\x01\x00\x00\x00\x4d\x08\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x04\x01\x00\x00\x00\x50\x04\x00\x00\x00\x08\x00\x00\x00\x42\x01\x00\x00\x00\x53\x20\x00\x00\x00\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x04\x01\x00\x00\x00\x56\x04\x00\x00\x00\x13\x00\x00\x00\x00\x00\x04\x00\x00\x00\x0d\x0a\x0d\x0a\xed\x5b\xd6\x7f\x65\x86\xe4\x59\xf1\xa0\x5d\xbe\xae\x4a\xaa\x72\x9a\x6b\x85\x51\x83\x87\x2a\xc4\x65\xaf\x2d\x5c\x5b\x77\x1d\x6d";

    var fbs = std.io.fixedBufferStream(s);

    const header = try Header.readAlloc(fbs.reader(), std.testing.allocator);
    defer header.deinit();

    const cid = header.getCipherId();
    try std.testing.expectEqual(Field.Cipher.aes256_cbc, cid);

    const comp = header.getCompression();
    try std.testing.expectEqual(Field.Compression.gzip, comp);

    const seed = header.getMainSeed();
    try std.testing.expectEqualSlices(u8, "\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78", &seed);

    const iv = header.getEncryptionIv();
    try std.testing.expectEqualSlices(u8, "\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78", &iv);

    const kdf = header.getKdfParameters();
    try std.testing.expectEqualSlices(u8, "\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78", &kdf.argon2.s);
    try std.testing.expectEqual(@as(u64, 2), kdf.argon2.i);
    try std.testing.expectEqual(@as(u64, 0x40000000), kdf.argon2.m);
    try std.testing.expectEqual(@as(u32, 8), kdf.argon2.p);
    try std.testing.expectEqual(@as(u32, 0x13), kdf.argon2.v);
}

const db = @embedFile("static/testdb.kdbx");
const db2 = @embedFile("static/TestDb2.kdbx");

test "verify kdbx4 header mac (positive test)" {
    var fbs = std.io.fixedBufferStream(db);

    const header = try Header.readAlloc(fbs.reader(), std.testing.allocator);
    defer header.deinit();

    var keys = try header.deriveKeys("supersecret", null, null);
    defer keys.deinit();

    try header.checkMac(&keys);
}

test "verify kdbx4 header mac (negative test)" {
    var fbs = std.io.fixedBufferStream(db);

    const header = try Header.readAlloc(fbs.reader(), std.testing.allocator);
    defer header.deinit();

    var keys = try header.deriveKeys("Supersecret", null, null);
    defer keys.deinit();

    try std.testing.expectError(error.Authenticity, header.checkMac(&keys));
}

test "the decryption of a kdbx4 file #1" {
    var fbs = std.io.fixedBufferStream(db);
    const reader = fbs.reader();

    const header = try Header.readAlloc(reader, std.testing.allocator);
    defer header.deinit();

    var keys = try header.deriveKeys("supersecret", null, null);
    defer keys.deinit();
    try header.checkMac(&keys);

    var body = try Body.readAlloc(reader, &header, &keys, std.testing.allocator);
    defer body.deinit();

    try std.testing.expectEqual(InnerHeader.StreamCipher.ChaCha20, body.inner_header.stream_cipher);

    //std.debug.print("{s}", .{std.fmt.fmtSliceHexLower(body.inner_header.stream_key)});
    //std.debug.print("{s}\n", .{body.xml});

    const body_xml = try body.getXml(std.testing.allocator);
    defer body_xml.deinit();

    // Meta
    try std.testing.expectEqualSlices(u8, "KeePassXC", body_xml.meta.generator);
    try std.testing.expectEqualSlices(u8, "Test Database", body_xml.meta.database_name);
    try std.testing.expectEqual(@as(i64, 63860739034), body_xml.meta.database_name_changed);
    try std.testing.expectEqualSlices(u8, "This is a test database", body_xml.meta.database_description.?);
    try std.testing.expectEqual(@as(i64, 365), body_xml.meta.maintenance_history_days);
    try std.testing.expectEqual(@as(i64, -1), body_xml.meta.master_key_change_rec);
    try std.testing.expectEqual(@as(i64, -1), body_xml.meta.master_key_change_force);
    try std.testing.expectEqual(false, body_xml.meta.memory_protection.protect_title);
    try std.testing.expectEqual(false, body_xml.meta.memory_protection.protect_user_name);
    try std.testing.expectEqual(true, body_xml.meta.memory_protection.protect_password);
    try std.testing.expectEqual(false, body_xml.meta.memory_protection.protect_url);
    try std.testing.expectEqual(false, body_xml.meta.memory_protection.protect_notes);
    try std.testing.expectEqual(true, body_xml.meta.recycle_bin_enabled);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.meta.recycle_bin_uuid);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.meta.entry_template_group);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.meta.last_selected_group);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.meta.last_top_visible_group);
    try std.testing.expectEqual(@as(i64, 10), body_xml.meta.history_max_items);
    try std.testing.expectEqual(@as(i64, 6291456), body_xml.meta.history_max_size);

    try std.testing.expectEqualSlices(u8, "KPXC_DECRYPTION_TIME_PREFERENCE", body_xml.meta.custom_data.items[0].key);
    try std.testing.expectEqualSlices(u8, "100", body_xml.meta.custom_data.items[0].value);

    try std.testing.expectEqualSlices(u8, "KPXC_RANDOM_SLUG", body_xml.meta.custom_data.items[1].key);
    try std.testing.expectEqualSlices(u8, "998be628c7527f3496dd5ec88960ea9f0542cb3196d83200f257d38f24ed234e93550d2db8f784084dc387601ad233416875951170c4cedf969be95ef0654b69e8893133e1a2982c76c16aabca5dd756b1d3549f5efe96f236611239e28c75e5277a7791a1aa557a9413201a76266fdd6edfba5ec4ad5c80af", body_xml.meta.custom_data.items[1].value);

    try std.testing.expectEqualSlices(u8, "_LAST_MODIFIED", body_xml.meta.custom_data.items[2].key);
    try std.testing.expectEqualSlices(u8, "Sat Aug 31 22:13:03 2024 GMT", body_xml.meta.custom_data.items[2].value);

    // Root Group
    try std.testing.expectEqualSlices(u8, "4c366769-07e8-4bc9-8091-3e5caefe9710", &Uuid.urn.serialize(body_xml.root.uuid));
    try std.testing.expectEqualSlices(u8, "Root", body_xml.root.name);
    try std.testing.expectEqual(@as(i64, 48), body_xml.root.icon_id);
    try std.testing.expectEqual(true, body_xml.root.is_expanded);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.root.last_top_visible_entry);

    // Entry 0
    try std.testing.expectEqualSlices(u8, "0ff2cbb1-69d5-4fda-bb68-da67291dcb07", &Uuid.urn.serialize(body_xml.root.entries.items[0].uuid));
    try std.testing.expectEqual(@as(i64, 0), body_xml.root.entries.items[0].icon_id);
    try std.testing.expectEqualSlices(u8, "programming", body_xml.root.entries.items[0].tags.?);
    try std.testing.expectEqualSlices(u8, "", body_xml.root.entries.items[0].get("Notes").?);
    try std.testing.expectEqualSlices(u8, "123456", body_xml.root.entries.items[0].get("Password").?);
    try std.testing.expectEqualSlices(u8, "https://github.com", body_xml.root.entries.items[0].get("URL").?);
    try std.testing.expectEqualSlices(u8, "Github", body_xml.root.entries.items[0].get("Title").?);
    try std.testing.expectEqualSlices(u8, "max", body_xml.root.entries.items[0].get("UserName").?);

    // Entry 1
    try std.testing.expectEqualSlices(u8, "164b7b20-7220-4471-aebf-3023a704b2f4", &Uuid.urn.serialize(body_xml.root.entries.items[1].uuid));
    try std.testing.expectEqual(@as(i64, 0), body_xml.root.entries.items[1].icon_id);
    try std.testing.expectEqualSlices(u8, "", body_xml.root.entries.items[1].tags.?);
    try std.testing.expectEqualSlices(u8, "", body_xml.root.entries.items[1].get("Notes").?);
    try std.testing.expectEqualSlices(u8, "654321", body_xml.root.entries.items[1].get("Password").?);
    try std.testing.expectEqualSlices(u8, "https://codeberg.org", body_xml.root.entries.items[1].get("URL").?);
    try std.testing.expectEqualSlices(u8, "Codeberg", body_xml.root.entries.items[1].get("Title").?);
    try std.testing.expectEqualSlices(u8, "max", body_xml.root.entries.items[1].get("UserName").?);
}

test "the decryption of a kdbx4 file #2" {
    var fbs = std.io.fixedBufferStream(db2);
    const reader = fbs.reader();

    const header = try Header.readAlloc(reader, std.testing.allocator);
    defer header.deinit();

    var keys = try header.deriveKeys("foobar", null, null);
    defer keys.deinit();
    try header.checkMac(&keys);

    var body = try Body.readAlloc(reader, &header, &keys, std.testing.allocator);
    defer body.deinit();

    try std.testing.expectEqual(InnerHeader.StreamCipher.ChaCha20, body.inner_header.stream_cipher);

    //std.debug.print("{s}\n", .{body.xml});

    const body_xml = try body.getXml(std.testing.allocator);
    defer body_xml.deinit();

    // Meta
    try std.testing.expectEqualSlices(u8, "KeePassXC", body_xml.meta.generator);
    try std.testing.expectEqualSlices(u8, "Zig Database Impl", body_xml.meta.database_name);
    try std.testing.expectEqualSlices(u8, "This is another test database for the KDBX4 Zig impl", body_xml.meta.database_description.?);
    try std.testing.expectEqual(@as(i64, 365), body_xml.meta.maintenance_history_days);
    try std.testing.expectEqual(@as(i64, -1), body_xml.meta.master_key_change_rec);
    try std.testing.expectEqual(@as(i64, -1), body_xml.meta.master_key_change_force);
    try std.testing.expectEqual(false, body_xml.meta.memory_protection.protect_title);
    try std.testing.expectEqual(false, body_xml.meta.memory_protection.protect_user_name);
    try std.testing.expectEqual(true, body_xml.meta.memory_protection.protect_password);
    try std.testing.expectEqual(false, body_xml.meta.memory_protection.protect_url);
    try std.testing.expectEqual(false, body_xml.meta.memory_protection.protect_notes);
    try std.testing.expectEqual(true, body_xml.meta.recycle_bin_enabled);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.meta.recycle_bin_uuid);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.meta.entry_template_group);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.meta.last_selected_group);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.meta.last_top_visible_group);
    try std.testing.expectEqual(@as(i64, 10), body_xml.meta.history_max_items);
    try std.testing.expectEqual(@as(i64, 6291456), body_xml.meta.history_max_size);

    // Custom icon
    try std.testing.expectEqual(@as(usize, 1), body_xml.meta.custom_icons.?.items.len);
    try std.testing.expectEqualSlices(u8, "ba5c5602-21dc-464e-ab87-014d487a74c1", &Uuid.urn.serialize(body_xml.meta.custom_icons.?.items[0].uuid));
    try std.testing.expectEqualSlices(u8, "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEnRFWHRfcV9pY29PcmlnRGVwdGgAMzLV4rjsAAAEl0lEQVRYha1XUWhbVRj+vnPTNNvaSNnuTZpkJY4ryJ1uD3UrIjL3Ioo6fRLZ08CHKjIRHfowWJbpFHzQiUN9EB8F6YNlKMM5GRsozjnRDqpgkNgmze1Nts60KW2a5PdhyXaX3LTZmu8p5//P/3/fOffk/88hOoRlWf65QmGvAPsgYgGICBkBAIrMAJgBOUng1MCWLecmJyfLneTlWhPiuh5eIhMish9AsEO9RZJfBkSS6XzevisBpmn2LhSLhwG8LiKbOiS+PTlZAvBBXzB4PJVKLXcsoL7qcREZuRtiDyEXAyLPee1Gi4CYYeyoiHwrQKwb5C6ijI98KuM4E20FxHU9vARc6ja5W0QA2OXeCdX4YZpm7xI57iYn8CeBr0hevQu+6wTGCPzWMAgQWyLHTdPsbRGwUCwebv7mJE/Y+fwL91tWGEq9CNKuOxZAXiFwgcB5kBMA/qvHXCNwcLOuh+x8/nmSx905RWSkfrgbi7x56FLNp52attu27UuNsaXrfdc0bWh0dPSvZDJZa0rMWCx2n6Zp+ampqbmGPRQK3Yta7Z+mhZUCImY6n7cJAGHD+FREXmreQ+XzPZTL5S577W+nGBwcHKpVKv8220l+ZjvOy8qyLH+9yLSiWrXWQw4AIrK9jX2/ZVl+NVco7IVHhSNZgqZdWK8ATdN+IVnwcAXnCoW9SoB9bWKP5XK5lq27U2Sz2asQedPLJ8A+VW8sLfD5/V+vl7yBwKZN3rlELAUg0mwnWZqenk51S0A6nb5OcsrDFVGNltoEh6R0SwAAQGS2xURGFF3F6NZc2dJVcgAgW3ISUAqA1wntD4VCRre44/F4AB6fGkBeAfC8MCiRx7slYHlxcY+I9Hq4bEWRn72CRORVEVnzxtQJBHjNy06Riwrk+TZBuwZDoTfWSx7W9QMi8oSnkzyvggMD3wOY9xQh8n7YMI4NDw/33ClxIpFQYcM4JMDnbabMD4icaTSjkyLySl3Vhxr5a1XkLYjsAAAC0yC/UMCPyu+/nMlkrnll3LZt2z2lUmlYAQ/XRA5AxGwnkEqdtGdnDyoA8ImcIFkGAN4IzG8WeQTk7wAgwFYRSVRFzqyUy6cSiUTLXxcAFufnx1Gr/VCr1d5ZlZxc7hE5UV/cDYQNIykiR+rDos/v305yQ6Vc/sldFzSlnp2ZnT3llTgcDj8m1eq5dsQuAUnbcY4CriLUFwy+W7/ZAECwWi4nM5nM3wGRB0keAvCRIkc39vd/1y6xz+ebaOdzsU/0BYPv3Ry6fZFIZGt1ZeUigEEAVWraM7Ztn14zqQshXV8B4Gvjzmk9PSMzMzPTngIAIGoYOysip2+KIM8COEtgXoDQo3v2HB8bG6uuIqACQPMi95FPZh3nD7fRs9BEo9FYZWXlG4jsbPZt1vXe1d59IV2vorm/kFeUpj2dy+VaOqLnac5ms5n+YHCEZJLkbU+qxcVFzxg33S1elkm+vWHjxt1e5G0FAEAqlVq2HedoD7CdSn0MoAhyIR6PV1ZlJ+dALpD8xOf3P2A7zpF0Or20hui1Yel639DQ0MBa86LRaMw0zU5f0fgfUk/VbnmdnBIAAAAASUVORK5CYII=", body_xml.meta.custom_icons.?.items[0].data);

    // Entry 0
    try std.testing.expectEqualSlices(u8, "5dd56835-af4c-49a3-aa67-f458f18397ef", &Uuid.urn.serialize(body_xml.root.entries.items[0].uuid));
    try std.testing.expectEqualSlices(u8, "ba5c5602-21dc-464e-ab87-014d487a74c1", &Uuid.urn.serialize(body_xml.root.entries.items[0].custom_icon_uuid.?));
    try std.testing.expectEqual(@as(i64, 0), body_xml.root.entries.items[0].icon_id);
    try std.testing.expectEqualSlices(u8, "dev,programming", body_xml.root.entries.items[0].tags.?);
    try std.testing.expectEqualSlices(u8, "Recovery keys:\n\n123-456-789\n123-456-789", body_xml.root.entries.items[0].get("Notes").?);
    try std.testing.expectEqualSlices(u8, "4~+aSX=&=~u;7a$XrjML", body_xml.root.entries.items[0].get("Password").?);
    try std.testing.expectEqualSlices(u8, "https://github.com", body_xml.root.entries.items[0].get("URL").?);
    try std.testing.expectEqualSlices(u8, "Github", body_xml.root.entries.items[0].get("Title").?);
    try std.testing.expectEqualSlices(u8, "max123", body_xml.root.entries.items[0].get("UserName").?);

    // Entry 1
    try std.testing.expectEqualSlices(u8, "66a6757f-76e2-47a6-b828-5cb907cc99f7", &Uuid.urn.serialize(body_xml.root.entries.items[1].uuid));
    try std.testing.expect(body_xml.root.entries.items[1].custom_icon_uuid == null);
    try std.testing.expectEqual(@as(i64, 0), body_xml.root.entries.items[1].icon_id);
    try std.testing.expectEqualSlices(u8, "coding,programming", body_xml.root.entries.items[1].tags.?);
    try std.testing.expectEqualSlices(u8, "", body_xml.root.entries.items[1].get("Notes").?);
    try std.testing.expectEqualSlices(u8, "L&%)o[d3~)L8`BJ>1t\\h", body_xml.root.entries.items[1].get("Password").?);
    try std.testing.expectEqualSlices(u8, "https://codeberg.de", body_xml.root.entries.items[1].get("URL").?);
    try std.testing.expectEqualSlices(u8, "Codeberg", body_xml.root.entries.items[1].get("Title").?);
    try std.testing.expectEqualSlices(u8, "max@web.de", body_xml.root.entries.items[1].get("UserName").?);

    // Root / Work
    try std.testing.expectEqualSlices(u8, "Work", body_xml.root.groups.items[0].name);

    // Root / Work . Entry 0
    try std.testing.expectEqualSlices(u8, "ZzIE!7ml-HT3c$i;48ZY", body_xml.root.groups.items[0].entries.items[0].get("Password").?);

    // Root / Work . Entry 1
    try std.testing.expectEqualSlices(u8, "7532", body_xml.root.groups.items[0].entries.items[1].get("Password").?);

    // Root / Work / Project One
    try std.testing.expectEqualSlices(u8, "Project One", body_xml.root.groups.items[0].groups.items[0].name);

    // Root / Work / Project One
    try std.testing.expectEqualSlices(u8, "21c0be125544bd4f1e8c3503294ef4fb40bf212d04a7ab4ecfe2d46442585febd115385eb48d45ca34e7726a5762b0ea2fe2271130dce00f83ad5c8620689b0c1ca2fa9a174dced7a9a68a0b3caec10d", body_xml.root.groups.items[0].groups.items[0].entries.items[0].get("Key").?);

    // Root / Shopping
    try std.testing.expectEqualSlices(u8, "Shopping", body_xml.root.groups.items[1].name);

    // Root / Shopping . Entry 0
    try std.testing.expectEqualSlices(u8, "4[PXs~cVy^*YD;Y}MI5~", body_xml.root.groups.items[1].entries.items[0].get("Password").?);

    // Root / Shopping . Entry 1
    try std.testing.expectEqualSlices(u8, "s]{)iQd#6[pyU8:.hpel", body_xml.root.groups.items[1].entries.items[1].get("Password").?);

    // Root / KeePassXC-Browser Passwords
    try std.testing.expectEqualSlices(u8, "KeePassXC-Browser Passwords", body_xml.root.groups.items[2].name);
    try std.testing.expectEqualSlices(u8, "OfRg2GQ4WiRHNtnrOWhalG-5iw-gXKq_JVaUnWqpeRc", body_xml.root.groups.items[2].entries.items[0].get("KPEX_PASSKEY_CREDENTIAL_ID").?);
    try std.testing.expectEqualSlices(u8, "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfVXUrA29p2LnqC3T\nB/qindmNV+y+6+Cn5AwH/j3Iz0+hRANCAAQRKLuox37xlTHnumSyvTMlHh1VML2e\nSxtYwceA/pq1gSM3XORnXwnscNBaEJG81HJp6+T5MiimPts7VwUj9G0s\n-----END PRIVATE KEY-----\n", body_xml.root.groups.items[2].entries.items[0].get("KPEX_PASSKEY_PRIVATE_KEY_PEM").?);
    try std.testing.expectEqualSlices(u8, "passkey.org", body_xml.root.groups.items[2].entries.items[0].get("KPEX_PASSKEY_RELYING_PARTY").?);
    try std.testing.expectEqualSlices(u8, "peter", body_xml.root.groups.items[2].entries.items[0].get("KPEX_PASSKEY_USERNAME").?);
    try std.testing.expectEqualSlices(u8, "DEMO__9fX19ERU1P", body_xml.root.groups.items[2].entries.items[0].get("KPEX_PASSKEY_USER_HANDLE").?);
}

test "xml tests" {
    _ = xml;
}

test "serialize Times to XML" {
    const t = Times{
        .last_modification_time = 0x0edbb52295,
        .creation_time = 0x0edbb37087,
        .last_access_time = 0x0edbb52295,
        .expiry_time = 0x0edbb37087,
        .expires = false,
        .usage_count = 0,
        .location_changed = 0x0edbb37091,
    };

    var arr = std.ArrayList(u8).init(std.testing.allocator);
    defer arr.deinit();

    try t.toXml(arr.writer(), 0, std.testing.allocator);

    const expected: []const u8 =
        \\<Times>
        \\  <LastModificationTime>lSK12w4AAAA=</LastModificationTime>
        \\  <CreationTime>h3Cz2w4AAAA=</CreationTime>
        \\  <LastAccessTime>lSK12w4AAAA=</LastAccessTime>
        \\  <ExpiryTime>h3Cz2w4AAAA=</ExpiryTime>
        \\  <Expires>False</Expires>
        \\  <UsageCount>0</UsageCount>
        \\  <LocationChanged>kXCz2w4AAAA=</LocationChanged>
        \\</Times>
        \\
    ;

    try std.testing.expectEqualSlices(u8, expected, arr.items);
}

test "serialize AutoType to XML" {
    const t = AutoType{
        .enabled = true,
        .data_transfer_obfuscation = 0,
        .default_sequence = null,
    };

    var arr = std.ArrayList(u8).init(std.testing.allocator);
    defer arr.deinit();

    try t.toXml(arr.writer(), 0, std.testing.allocator);

    const expected: []const u8 =
        \\<AutoType>
        \\  <Enabled>True</Enabled>
        \\  <DataTransferObfuscation>0</DataTransferObfuscation>
        \\  <DefaultSequence/>
        \\</AutoType>
        \\
    ;

    try std.testing.expectEqualSlices(u8, expected, arr.items);
}

test "serialize entry #1" {
    const allocator = std.testing.allocator;

    const expected =
        \\<Entry>
        \\  <UUID>D/LLsWnVT9q7aNpnKR3LBw==</UUID>
        \\  <IconID>0</IconID>
        \\  <ForegroundColor/>
        \\  <BackgroundColor/>
        \\  <OverrideURL/>
        \\  <Tags>programming</Tags>
        \\  <Times>
        \\    <LastModificationTime>Noxl3g4AAAA=</LastModificationTime>
        \\    <CreationTime>HIxl3g4AAAA=</CreationTime>
        \\    <LastAccessTime>Noxl3g4AAAA=</LastAccessTime>
        \\    <ExpiryTime>HIxl3g4AAAA=</ExpiryTime>
        \\    <Expires>False</Expires>
        \\    <UsageCount>0</UsageCount>
        \\    <LocationChanged>Noxl3g4AAAA=</LocationChanged>
        \\  </Times>
        \\  <String>
        \\    <Key>Notes</Key>
        \\    <Value/>
        \\  </String>
        \\  <String>
        \\    <Key>Password</Key>
        \\    <Value Protected="True">h16dtqbi</Value>
        \\  </String>
        \\  <String>
        \\    <Key>Title</Key>
        \\    <Value>Github</Value>
        \\  </String>
        \\  <String>
        \\    <Key>URL</Key>
        \\    <Value>https://github.com</Value>
        \\  </String>
        \\  <String>
        \\    <Key>UserName</Key>
        \\    <Value>max</Value>
        \\  </String>
        \\  <AutoType>
        \\    <Enabled>True</Enabled>
        \\    <DataTransferObfuscation>0</DataTransferObfuscation>
        \\    <DefaultSequence/>
        \\  </AutoType>
        \\  <History/>
        \\</Entry>
        \\
    ;

    var arr = std.ArrayList(KeyValue).init(allocator);

    try arr.append(KeyValue{
        .key = try allocator.dupe(u8, "Notes"),
        .value = try allocator.dupe(u8, ""),
    });
    try arr.append(KeyValue{
        .key = try allocator.dupe(u8, "Password"),
        .value = try allocator.dupe(u8, "123456"),
        .protected = true,
    });
    try arr.append(KeyValue{
        .key = try allocator.dupe(u8, "Title"),
        .value = try allocator.dupe(u8, "Github"),
    });
    try arr.append(KeyValue{
        .key = try allocator.dupe(u8, "URL"),
        .value = try allocator.dupe(u8, "https://github.com"),
    });
    try arr.append(KeyValue{
        .key = try allocator.dupe(u8, "UserName"),
        .value = try allocator.dupe(u8, "max"),
    });

    const entry = Entry{
        .uuid = try Uuid.urn.deserialize("0ff2cbb1-69d5-4fda-bb68-da67291dcb07"),
        .icon_id = 0,
        .tags = try allocator.dupe(u8, "programming"),
        .times = .{
            .last_modification_time = 63860739126,
            .creation_time = 63860739100,
            .last_access_time = 63860739126,
            .expiry_time = 63860739100,
            .expires = false,
            .usage_count = 0,
            .location_changed = 63860739126,
        },
        .strings = arr,
        .auto_type = .{
            .enabled = true,
            .data_transfer_obfuscation = 0,
        },
        .allocator = allocator,
    };
    defer entry.deinit();

    var digest: [64]u8 = .{0} ** 64;
    std.crypto.hash.sha2.Sha512.hash("\xaa\xc0\x53\xb5\x37\x5b\xb0\x93\xba\xd1\xcb\x42\xae\xf1\x83\x23\xde\x86\x72\x2e\x49\x30\xa7\xac\x22\x69\x6d\x64\x24\x7b\xfc\x79\x3d\x58\xa7\x1e\xf0\x5b\x35\x52\x6f\x87\x26\xb3\x55\x57\x22\x2d\xb0\xfa\x62\x00\x2d\x6d\x5e\x96\x21\x7e\xf8\x7f\x72\x87\x13\xc7", &digest, .{});

    var chacha20 = ChaCha20.init(
        0,
        digest[0..32].*,
        digest[32..44].*,
    );

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();

    try entry.toXml(out.writer(), 0, &chacha20);

    try std.testing.expectEqualSlices(u8, expected, out.items);
}

test "serialize entry #2" {
    const allocator = std.testing.allocator;

    const expected =
        \\<Group>
        \\  <UUID>TDZnaQfoS8mAkT5crv6XEA==</UUID>
        \\  <Name>Root</Name>
        \\  <Notes/>
        \\  <IconID>48</IconID>
        \\  <Times>
        \\    <LastModificationTime>b4xl3g4AAAA=</LastModificationTime>
        \\    <CreationTime>0Itl3g4AAAA=</CreationTime>
        \\    <LastAccessTime>b4xl3g4AAAA=</LastAccessTime>
        \\    <ExpiryTime>0Itl3g4AAAA=</ExpiryTime>
        \\    <Expires>False</Expires>
        \\    <UsageCount>0</UsageCount>
        \\    <LocationChanged>0Itl3g4AAAA=</LocationChanged>
        \\  </Times>
        \\  <IsExpanded>True</IsExpanded>
        \\  <DefaultAutoTypeSequence/>
        \\  <EnableAutoType>null</EnableAutoType>
        \\  <EnableSearching>null</EnableSearching>
        \\  <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>
        \\  <Entry>
        \\    <UUID>D/LLsWnVT9q7aNpnKR3LBw==</UUID>
        \\    <IconID>0</IconID>
        \\    <ForegroundColor/>
        \\    <BackgroundColor/>
        \\    <OverrideURL/>
        \\    <Tags>programming</Tags>
        \\    <Times>
        \\      <LastModificationTime>Noxl3g4AAAA=</LastModificationTime>
        \\      <CreationTime>HIxl3g4AAAA=</CreationTime>
        \\      <LastAccessTime>Noxl3g4AAAA=</LastAccessTime>
        \\      <ExpiryTime>HIxl3g4AAAA=</ExpiryTime>
        \\      <Expires>False</Expires>
        \\      <UsageCount>0</UsageCount>
        \\      <LocationChanged>Noxl3g4AAAA=</LocationChanged>
        \\    </Times>
        \\    <String>
        \\      <Key>Notes</Key>
        \\      <Value/>
        \\    </String>
        \\    <String>
        \\      <Key>Password</Key>
        \\      <Value Protected="True">h16dtqbi</Value>
        \\    </String>
        \\    <String>
        \\      <Key>Title</Key>
        \\      <Value>Github</Value>
        \\    </String>
        \\    <String>
        \\      <Key>URL</Key>
        \\      <Value>https://github.com</Value>
        \\    </String>
        \\    <String>
        \\      <Key>UserName</Key>
        \\      <Value>max</Value>
        \\    </String>
        \\    <AutoType>
        \\      <Enabled>True</Enabled>
        \\      <DataTransferObfuscation>0</DataTransferObfuscation>
        \\      <DefaultSequence/>
        \\    </AutoType>
        \\    <History/>
        \\  </Entry>
        \\  <Entry>
        \\    <UUID>Fkt7IHIgRHGuvzAjpwSy9A==</UUID>
        \\    <IconID>0</IconID>
        \\    <ForegroundColor/>
        \\    <BackgroundColor/>
        \\    <OverrideURL/>
        \\    <Tags/>
        \\    <Times>
        \\      <LastModificationTime>b4xl3g4AAAA=</LastModificationTime>
        \\      <CreationTime>OIxl3g4AAAA=</CreationTime>
        \\      <LastAccessTime>b4xl3g4AAAA=</LastAccessTime>
        \\      <ExpiryTime>OIxl3g4AAAA=</ExpiryTime>
        \\      <Expires>False</Expires>
        \\      <UsageCount>0</UsageCount>
        \\      <LocationChanged>b4xl3g4AAAA=</LocationChanged>
        \\    </Times>
        \\    <String>
        \\      <Key>Notes</Key>
        \\      <Value/>
        \\    </String>
        \\    <String>
        \\      <Key>Password</Key>
        \\      <Value Protected="True">BY1N++nX</Value>
        \\    </String>
        \\    <String>
        \\      <Key>Title</Key>
        \\      <Value>Codeberg</Value>
        \\    </String>
        \\    <String>
        \\      <Key>URL</Key>
        \\      <Value>https://codeberg.org</Value>
        \\    </String>
        \\    <String>
        \\      <Key>UserName</Key>
        \\      <Value>max</Value>
        \\    </String>
        \\    <AutoType>
        \\      <Enabled>True</Enabled>
        \\      <DataTransferObfuscation>0</DataTransferObfuscation>
        \\      <DefaultSequence/>
        \\    </AutoType>
        \\    <History/>
        \\  </Entry>
        \\</Group>
        \\
    ;

    var entry1 = Entry{
        .uuid = try Uuid.urn.deserialize("0ff2cbb1-69d5-4fda-bb68-da67291dcb07"),
        .icon_id = 0,
        .tags = try allocator.dupe(u8, "programming"),
        .times = .{
            .last_modification_time = 63860739126,
            .creation_time = 63860739100,
            .last_access_time = 63860739126,
            .expiry_time = 63860739100,
            .expires = false,
            .usage_count = 0,
            .location_changed = 63860739126,
        },
        .strings = std.ArrayList(KeyValue).init(allocator),
        .auto_type = .{
            .enabled = true,
            .data_transfer_obfuscation = 0,
        },
        .allocator = allocator,
    };
    try entry1.set("Notes", "", false);
    try entry1.set("Password", "123456", true);
    try entry1.set("Title", "Github", false);
    try entry1.set("URL", "https://github.com", false);
    try entry1.set("UserName", "max", false);
    entry1.times = .{
        .last_modification_time = 63860739126,
        .creation_time = 63860739100,
        .last_access_time = 63860739126,
        .expiry_time = 63860739100,
        .expires = false,
        .usage_count = 0,
        .location_changed = 63860739126,
    };

    var entry2 = Entry{
        .uuid = try Uuid.urn.deserialize("164b7b20-7220-4471-aebf-3023a704b2f4"),
        .icon_id = 0,
        .tags = null,
        .times = .{
            .last_modification_time = 0x0ede658c6f,
            .creation_time = 0x0ede658c38,
            .last_access_time = 0x0ede658c6f,
            .expiry_time = 0x0ede658c38,
            .expires = false,
            .usage_count = 0,
            .location_changed = 0x0ede658c6f,
        },
        .strings = std.ArrayList(KeyValue).init(allocator),
        .auto_type = .{
            .enabled = true,
            .data_transfer_obfuscation = 0,
        },
        .allocator = allocator,
    };
    try entry2.set("Notes", "", false);
    try entry2.set("Password", "654321", true);
    try entry2.set("Title", "Codeberg", false);
    try entry2.set("URL", "https://codeberg.org", false);
    try entry2.set("UserName", "max", false);
    entry2.times = .{
        .last_modification_time = 0x0ede658c6f,
        .creation_time = 0x0ede658c38,
        .last_access_time = 0x0ede658c6f,
        .expiry_time = 0x0ede658c38,
        .expires = false,
        .usage_count = 0,
        .location_changed = 0x0ede658c6f,
    };

    var group = Group{
        .uuid = try Uuid.urn.deserialize("4c366769-07e8-4bc9-8091-3e5caefe9710"),
        .name = try allocator.dupe(u8, "Root"),
        .notes = null,
        .icon_id = 48,
        .times = .{
            .last_modification_time = 0x0ede658c6f,
            .creation_time = 0x0ede658bd0,
            .last_access_time = 0x0ede658c6f,
            .expiry_time = 0x0ede658bd0,
            .expires = false,
            .usage_count = 0,
            .location_changed = 0x0ede658bd0,
        },
        .is_expanded = true,
        .default_auto_type_sequence = null,
        .enable_auto_type = null,
        .enable_searching = null,
        .last_top_visible_entry = 0,
        .previous_parent_group = null,
        .entries = std.ArrayList(Entry).init(allocator),
        .groups = std.ArrayList(Group).init(allocator),
        .allocator = allocator,
    };
    defer group.deinit();

    try group.entries.append(entry1);
    try group.entries.append(entry2);

    var digest: [64]u8 = .{0} ** 64;
    std.crypto.hash.sha2.Sha512.hash("\xaa\xc0\x53\xb5\x37\x5b\xb0\x93\xba\xd1\xcb\x42\xae\xf1\x83\x23\xde\x86\x72\x2e\x49\x30\xa7\xac\x22\x69\x6d\x64\x24\x7b\xfc\x79\x3d\x58\xa7\x1e\xf0\x5b\x35\x52\x6f\x87\x26\xb3\x55\x57\x22\x2d\xb0\xfa\x62\x00\x2d\x6d\x5e\x96\x21\x7e\xf8\x7f\x72\x87\x13\xc7", &digest, .{});

    var chacha20 = ChaCha20.init(
        0,
        digest[0..32].*,
        digest[32..44].*,
    );

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();

    try group.toXml(out.writer(), 0, &chacha20);

    //std.debug.print("{s}\n", .{out.items});

    try std.testing.expectEqualSlices(u8, expected, out.items);
}
