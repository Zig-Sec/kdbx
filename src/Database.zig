//! A KDBX `Database`.
//!
//! Currently supported versions: `4.0`, `4.1`.

const std = @import("std");
const Uuid = @import("uuid");
const ChaCha20 = @import("chacha.zig").ChaCha20;

const Allocator = std.mem.Allocator;

const misc = @import("misc.zig");
const currTime = misc.currTime;

const gzip = @import("gzip.zig");

const v4 = @import("v4.zig");
const Field = v4.Field;
const Header = v4.Header;
const HVersion = v4.HVersion;
const XML = v4.XML;
const Meta = v4.Meta;
const KeyValue = v4.KeyValue;
const Group = v4.Group;
const Entry = v4.Entry;
const InnerHeader = v4.InnerHeader;
const Body = v4.Body;

pub const DatabaseKey = @import("DatabaseKey.zig");

header: Header,
inner_header: InnerHeader,
body: XML,
allocator: Allocator,

pub const OpenOptions = struct {
    key: DatabaseKey,
    allocator: Allocator,
};

pub const NewDatabaseOptions = struct {
    generator: []const u8 = "KDBX4-Zig",
    name: []const u8 = "Database",
    description: []const u8 = "",
    encryption_algorithm: Field.Cipher = .aes256_cbc,
    allocator: Allocator,
};

pub fn deinit(self: *@This()) void {
    self.header.deinit();
    self.inner_header.deinit();
    self.body.deinit();
}

/// Open a `Database` from a reader.
///
/// After using the `Database` it should be closed using `Database.deinit`.
///
/// ## Arguments
///
/// * `reader` - A `Reader` that wraps the raw database data.
/// * `options` - Options on how to open the database.
pub fn open(reader: *std.Io.Reader, options: OpenOptions) !@This() {
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
        std.crypto.secureZero(u8, body.xml);
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

/// Create a new `Database`.
pub fn new(options: NewDatabaseOptions) !@This() {
    // Outer Header
    var header = Header{
        .version = HVersion.new(0x9AA2D903, 0xB54BFB67, 1, 4),
        .fields = .{null} ** 6,
        .raw_header = try options.allocator.dupe(u8, ""),
        .hash = .{0} ** 32,
        .mac = .{0} ** 32,
        .allocator = options.allocator,
    };
    errdefer header.deinit();

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

    // Inner Header
    const stream_key = try options.allocator.alloc(u8, 64);
    std.crypto.random.bytes(stream_key);
    var inner_header = InnerHeader{
        .stream_cipher = .ChaCha20,
        .stream_key = stream_key,
        .binary = .empty,
        .allocator = options.allocator,
    };
    errdefer inner_header.deinit();

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
        .custom_data = .empty,
        .allocator = options.allocator,
    };
    errdefer meta.deinit();

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
        .entries = .empty,
        .groups = .empty,
        .allocator = options.allocator,
    };
    errdefer group.deinit();

    const xml_ = XML{
        .meta = meta,
        .root = group,
    };

    return .{
        .header = header,
        .inner_header = inner_header,
        .body = xml_,
        .allocator = options.allocator,
    };
}

/// Save the `Database`.
///
/// ## Arguments
///
/// * `out` - A `Writer` to save the `Database` to.
/// * `db_key` - A composite key (usually just a password).
/// * `allocator` - An `Allocator`.
pub fn save(self: *@This(), out: *std.Io.Writer, db_key: DatabaseKey, allocator: Allocator) !void {
    // TODO: remove this as soon as the gzip bug has been fixed.
    if (self.header.getCompression() == .gzip) {
        std.log.warn(
            "unsupported compression method 'gzip' due to issue '{s}'",
            .{"https://github.com/Zig-Sec/kdbx/issues/4"},
        );
        std.log.warn("falling back to no compression for the database", .{});
        self.header.setCompression(.none);
        std.log.warn("compression disabled for the given database. This has NO security implications!", .{});
    }

    var keys = try self.header.deriveKeys(db_key);
    try self.header.updateRawHeader();
    self.header.updateHash();
    self.header.updateMac(&keys);

    // --------------------------------------------------

    try out.writeAll(self.header.raw_header);
    try out.writeAll(&self.header.hash);
    try out.writeAll(&self.header.mac);

    {
        var inner_ = std.Io.Writer.Allocating.init(allocator);
        defer inner_.deinit();
        const inner = &inner_.writer;

        try self.inner_header.write(inner);

        //std.debug.print("inner header: {s}", .{std.fmt.fmtSliceHexLower(inner_.items)});

        var digest: [64]u8 = .{0} ** 64;
        std.crypto.hash.sha2.Sha512.hash(self.inner_header.stream_key, &digest, .{});

        var cipher = ChaCha20.init(
            0,
            digest[0..32].*,
            digest[32..44].*,
        );

        try self.body.toXml(inner, &cipher);
        try inner.flush();

        //std.debug.print("{s}\n", .{inner_.items});

        // TODO: this block is more or less dead code as there is a
        // block at the bottom of this function disabling gzip if it
        // is enabled (see linked issue above).
        if (self.header.getCompression() == .gzip) {
            var in_stream = std.Io.Reader.fixed(inner_.written());

            var compressed = std.Io.Writer.Allocating.init(allocator);
            errdefer compressed.deinit();

            try gzip.compress(
                &in_stream,
                &compressed.writer,
                //.{ .level = .level_6 },
                .{},
            );

            try compressed.writer.flush();

            inner_.deinit();
            inner_ = compressed;
        }

        //std.log.err("gzip compressed: {x}\n", .{inner_.written()});

        var inner_data = inner_.toArrayList();
        defer inner_data.deinit(allocator);

        const iv = self.header.getEncryptionIv();
        switch (self.header.getCipherId()) {
            .aes128_cbc, .twofish_cbc, .chacha20 => {
                return error.UnsupportedCipher;
            },
            .aes256_cbc => {
                var xor_vector: [16]u8 = undefined;
                var j: usize = 0;

                if (inner_data.items.len % 16 != 0) {
                    // PKCS#7 padding
                    const l = @as(u8, @intCast(16 - (inner_data.items.len % 16)));
                    for (0..l) |_| try inner_data.append(allocator, l);
                }

                @memcpy(&xor_vector, iv[0..16]);
                var ctx = std.crypto.core.aes.Aes256.initEnc(keys.ekey);

                while (j < inner_data.items.len) : (j += 16) {
                    var data: [16]u8 = .{0} ** 16;
                    // The offset is always 16 except for the last block.
                    const offset = 16;
                    var in_: [16]u8 = .{0} ** 16;
                    @memcpy(in_[0..], inner_data.items[j .. j + offset]);

                    for (&in_, xor_vector) |*b1, b2| {
                        b1.* ^= b2;
                    }

                    ctx.encrypt(data[0..], &in_);
                    @memcpy(xor_vector[0..], data[0..]);
                    @memcpy(inner_data.items[j .. j + offset], data[0..offset]);
                }
            },
        }

        var i: usize = 0;
        var written: usize = 0;
        while (written < inner_data.items.len) {
            const to_write: u32 = if ((inner_data.items.len - written) < 1048576) @as(u32, @intCast(inner_data.items.len - written)) else 1048576;

            var raw_block_index: [8]u8 = .{0} ** 8;
            std.mem.writeInt(u64, &raw_block_index, i, .little);
            var raw_block_len: [4]u8 = .{0} ** 4;
            std.mem.writeInt(u32, &raw_block_len, to_write, .little);
            //std.debug.print("block length: {s}\n", .{std.fmt.fmtSliceHexLower(&raw_block_len)});
            const mac = keys.calculateMac(&.{
                &raw_block_index,
                &raw_block_len,
                inner_data.items[written .. written + to_write],
            }, i);

            try out.writeAll(&mac);
            try out.writeAll(&raw_block_len);
            try out.writeAll(inner_data.items[written .. written + to_write]);

            written += to_write;
            i += 1;
        }

        // The file is terminated by an empty block. Why is this important?!?
        // FUCK WHO KNOWS but KeePassXC and other applications expect it :|.
        // Instead, the header should encode the block length and the parser
        // is expected to stop if a block is less than the defined block length...
        // ... but whom be I to judge ...
        //
        // Maybe otherwise we don't know if the MAC has been calulated over "the
        // whole file" (in some sense...).
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
}

/// Get the root group of the given database.
pub fn getRoot(self: *@This()) *Group {
    return &self.body.root;
}

/// Get the group specified by `path`.
///
/// The `path` must start with a '/' (the root) followed by zero
/// or more group names, separated by a '/'.
///
/// Returns `null` if the group doesn't exist.
pub fn getGroup(self: *@This(), path: []const u8) ?*Group {
    // The path must start with a '/' (the root)
    if (path.len < 1 or path[0] != '/') return null;

    var g = self.getRoot();
    if (path.len < 2) return g;

    var iter = std.mem.splitAny(u8, path, "/");
    _ = iter.next(); // We skip the first, as we start with the '/'
    outer: while (iter.next()) |name| {
        for (g.groups.items) |*child_group| {
            if (std.mem.eql(u8, child_group.name, name)) {
                g = child_group;
                continue :outer;
            }
        } else return null;
    }

    return g;
}
