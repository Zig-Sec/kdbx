const std = @import("std");
const dishwasher = @import("dishwasher");
const Uuid = @import("uuid");
const ChaCha20 = @import("chacha.zig").ChaCha20;
const xml = @import("xml.zig");

const Allocator = std.mem.Allocator;

const misc = @import("misc.zig");
const decode = misc.decode;
const encode = misc.encode;
const encode2 = misc.encode2;

const v4 = @import("v4.zig");
const Field = v4.Field;
const Header = v4.Header;
const HVersion = v4.HVersion;
const Keys = v4.Keys;
const XML = v4.XML;
const Meta = v4.Meta;
const KeyValue = v4.KeyValue;
const Group = v4.Group;
const Entry = v4.Entry;
const Times = v4.Times;
const AutoType = v4.AutoType;
const Icon = v4.Icon;
const InnerHeader = v4.InnerHeader;
const Body = v4.Body;

const DatabaseKey = @import("DatabaseKey.zig");

// Why not just use fucking EPOCH
const TIME_DIFF_KDBX_EPOCH_IN_SEC = 62135600008;

header: Header,
inner_header: InnerHeader,
body: XML,
allocator: Allocator,

pub const OpenOptions = struct {
    key: DatabaseKey,
    allocator: Allocator,
};

pub fn deinit(self: *const @This()) void {
    self.header.deinit();
    self.inner_header.deinit();
    self.body.deinit();
}

pub fn open(reader: anytype, options: OpenOptions) !@This() {
    const header = try Header.readAlloc(
        reader,
        options.allocator,
    );
    errdefer header.deinit();

    var keys = try header.deriveKeys(options.key);
    defer keys.deinit();

    try header.checkMac(&keys);

    var body = try Body.readAlloc(
        reader,
        &header,
        &keys,
        options.allocator,
    );
    defer {
        std.crypto.utils.secureZero(u8, body.xml);
        body.allocator.free(body.xml);
    }

    const body_xml = try body.getXml(options.allocator);
    errdefer body_xml.deinit();

    return .{
        .header = header,
        .inner_header = body.inner_header,
        .body = body_xml,
        .allocator = options.allocator,
    };
}

pub const DatabaseOptions = struct {
    generator: []const u8 = "Zig KDBX4 Parser",
    name: []const u8 = "Database",
    description: []const u8 = "",
    encryption_algorithm: Field.Cipher = .aes256_cbc,
    password: []const u8,
    allocator: Allocator,
};

pub fn newDatabase(options: DatabaseOptions) ![]const u8 {
    // Outer Header
    var header = Header{
        .version = HVersion.new(0x9AA2D903, 0xB54BFB67, 1, 4),
        .fields = .{null} ** 6,
        .raw_header = try options.allocator.dupe(u8, ""),
        .hash = .{0} ** 32,
        .mac = .{0} ** 32,
        .allocator = options.allocator,
    };
    defer header.deinit();

    header.fields[0] = .{ .cipher_id = options.encryption_algorithm };
    header.fields[1] = .{ .compression = Field.Compression.gzip };

    var ms: [32]u8 = .{0} ** 32;
    std.crypto.random.bytes(&ms);
    header.fields[2] = .{ .main_seed = ms };

    var iv: [16]u8 = .{0} ** 16;
    std.crypto.random.bytes(&iv);
    header.fields[3] = .{ .encryption_iv = iv };

    var salt: [32]u8 = .{0} ** 32;
    std.crypto.random.bytes(&salt);
    header.fields[4] = .{
        .kdf_parameters = .{
            .argon2 = .{
                .s = salt,
                .p = 2,
                .m = 16777216,
                .i = 64,
                .v = 0x13, // v1.3
                .mode = .argon2id,
                .allocator = options.allocator,
            },
        },
    };

    var db_key = DatabaseKey{
        .password = try options.allocator.dupe(u8, options.password),
        .allocator = options.allocator,
    };
    defer db_key.deinit();
    var keys = try header.deriveKeys(db_key);
    try header.updateRawHeader();
    header.updateHash();
    header.updateMac(&keys);

    // Inner Header
    const stream_key = try options.allocator.alloc(u8, 64);
    std.crypto.random.bytes(stream_key);
    var inner_header = InnerHeader{
        .stream_cipher = .ChaCha20,
        .stream_key = stream_key,
        .binary = std.ArrayList([]u8).init(options.allocator),
        .allocator = options.allocator,
    };
    defer inner_header.deinit();

    // DB
    const t = currTime();
    var meta = Meta{
        .generator = try options.allocator.dupe(u8, options.generator),
        .database_name = try options.allocator.dupe(u8, options.name),
        .database_name_changed = t,
        .database_description = try options.allocator.dupe(u8, options.description),
        .database_description_changed = t,
        .default_user_name_changed = t,
        .maintenance_history_days = 365,
        .master_key_changed = t,
        .master_key_change_rec = -1,
        .master_key_change_force = -1,
        .memory_protection = .{},
        .custom_icons = null,
        .recycle_bin_enabled = true,
        .recycle_bin_uuid = 0,
        .recycle_bin_changed = t,
        .entry_template_group = 0,
        .entry_template_group_changed = t,
        .last_selected_group = 0,
        .last_top_visible_group = 0,
        .history_max_items = 10,
        .history_max_size = 6291456,
        .settings_changed = t,
        .custom_data = std.ArrayList(KeyValue).init(options.allocator),
        .allocator = options.allocator,
    };
    defer meta.deinit();

    var group = Group{
        .uuid = Uuid.v4.new(),
        .name = try options.allocator.dupe(u8, "Root"),
        .notes = null,
        .icon_id = 48,
        .times = .{
            .last_modification_time = t,
            .creation_time = t,
            .last_access_time = t,
            .expiry_time = t,
            .expires = false,
            .usage_count = 0,
            .location_changed = t,
        },
        .is_expanded = true,
        .default_auto_type_sequence = null,
        .enable_auto_type = null,
        .enable_searching = null,
        .last_top_visible_entry = 0,
        .previous_parent_group = null,
        .entries = std.ArrayList(Entry).init(options.allocator),
        .groups = std.ArrayList(Group).init(options.allocator),
        .allocator = options.allocator,
    };
    defer group.deinit();

    var xml_ = XML{
        .meta = meta,
        .root = group,
    };

    return try serializeDb(
        &header,
        &inner_header,
        &xml_,
        &keys,
        options.allocator,
    );
}

pub fn serializeDb(
    header: *Header,
    inner_header: *InnerHeader,
    xml_: *XML,
    keys: *Keys,
    allocator: Allocator,
) ![]const u8 {
    var out_ = std.ArrayList(u8).init(allocator);
    errdefer out_.deinit();
    var out = out_.writer();

    try out.writeAll(header.raw_header);
    try out.writeAll(&header.hash);
    try out.writeAll(&header.mac);

    {
        var inner_ = std.ArrayList(u8).init(allocator);
        defer inner_.deinit();
        const inner = inner_.writer();

        try inner_header.write(inner);

        //std.debug.print("inner header: {s}", .{std.fmt.fmtSliceHexLower(inner_.items)});

        var digest: [64]u8 = .{0} ** 64;
        std.crypto.hash.sha2.Sha512.hash(inner_header.stream_key, &digest, .{});

        var cipher = ChaCha20.init(
            0,
            digest[0..32].*,
            digest[32..44].*,
        );

        try xml_.toXml(inner, &cipher);

        if (header.getCompression() == .gzip) {
            var in_stream = std.io.fixedBufferStream(inner_.items);
            var compressed = std.ArrayList(u8).init(allocator);
            errdefer compressed.deinit();

            try std.compress.gzip.compress(
                in_stream.reader(),
                compressed.writer(),
                .{ .level = .level_6 },
            );

            inner_.deinit();
            inner_ = compressed;
        }

        //std.debug.print("{s}\n", .{std.fmt.fmtSliceHexLower(inner_.items)});

        const iv = header.getEncryptionIv();
        switch (header.getCipherId()) {
            .aes128_cbc, .twofish_cbc, .chacha20 => {
                return error.UnsupportedCipher;
            },
            .aes256_cbc => {
                var xor_vector: [16]u8 = undefined;
                var j: usize = 0;

                if (inner_.items.len % 16 != 0) {
                    // PKCS#7 padding
                    const l = @as(u8, @intCast(16 - (inner_.items.len % 16)));
                    for (0..l) |_| try inner_.append(l);
                }

                @memcpy(&xor_vector, iv[0..16]);
                var ctx = std.crypto.core.aes.Aes256.initEnc(keys.ekey);

                while (j < inner_.items.len) : (j += 16) {
                    var data: [16]u8 = .{0} ** 16;
                    // The offset is always 16 except for the last block.
                    const offset = 16;
                    var in_: [16]u8 = .{0} ** 16;
                    @memcpy(in_[0..], inner_.items[j .. j + offset]);

                    for (&in_, xor_vector) |*b1, b2| {
                        b1.* ^= b2;
                    }

                    ctx.encrypt(data[0..], &in_);
                    @memcpy(xor_vector[0..], data[0..]);
                    @memcpy(inner_.items[j .. j + offset], data[0..offset]);
                }
            },
        }

        var i: usize = 0;
        var written: usize = 0;
        while (written < inner_.items.len) {
            const to_write: u32 = if ((inner_.items.len - written) < 1048576) @as(u32, @intCast(inner_.items.len - written)) else 1048576;

            var raw_block_index: [8]u8 = .{0} ** 8;
            std.mem.writeInt(u64, &raw_block_index, i, .little);
            var raw_block_len: [4]u8 = .{0} ** 4;
            std.mem.writeInt(u32, &raw_block_len, to_write, .little);
            //std.debug.print("block length: {s}\n", .{std.fmt.fmtSliceHexLower(&raw_block_len)});
            const mac = keys.calculateMac(&.{
                &raw_block_index,
                &raw_block_len,
                inner_.items[written .. written + to_write],
            }, i);

            try out.writeAll(&mac);
            try out.writeAll(&raw_block_len);
            try out.writeAll(inner_.items[written .. written + to_write]);

            written += to_write;
            i += 1;
        }

        // The file is terminated by an empty block. Why is this important?!?
        // FUCK WHO KNOWS but KeePassXC and other applications expect it :|
        {
            var raw_block_index: [8]u8 = .{0} ** 8;
            std.mem.writeInt(u64, &raw_block_index, i, .little);
            var raw_block_len: [4]u8 = .{0} ** 4;
            std.mem.writeInt(u32, &raw_block_len, 0, .little);

            const mac = keys.calculateMac(&.{
                &raw_block_index,
                &raw_block_len,
                "",
            }, i);

            try out.writeAll(&mac);
            try out.writeAll(&raw_block_len);
        }
    }

    return try out_.toOwnedSlice();
}

fn currTime() i64 {
    return std.time.timestamp() + TIME_DIFF_KDBX_EPOCH_IN_SEC;
}
