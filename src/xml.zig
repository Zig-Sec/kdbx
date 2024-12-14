const std = @import("std");
const dishwasher = @import("dishwasher");
const Uuid = @import("uuid");
const ChaCha20 = @import("chacha.zig").ChaCha20;
const root = @import("root.zig");

const Allocator = std.mem.Allocator;
const Group = root.Group;
const Entry = root.Entry;
const Meta = root.Meta;
const Icon = root.Icon;
const KeyValue = root.KeyValue;
const AutoType = root.AutoType;
const Body = root.Body;
const XML = root.XML;

pub fn parseXml(self: *const Body, allocator: Allocator) !XML {
    const tree = try dishwasher.parseXmlFull(allocator, self.xml);
    defer tree.deinit();

    const file = tree.doc.root.elementByTagName("KeePassFile");
    if (file == null) return error.KeePassFileTagMissing;

    const meta = file.?.elementByTagName("Meta");
    if (meta == null) return error.MetaTagMissing;

    const meta_ = try parseMeta(meta.?, allocator);
    errdefer meta_.deinit();

    const root_ = file.?.elementByTagName("Root");
    if (root_ == null) return error.RootTagMissing;

    var digest: [64]u8 = .{0} ** 64;
    std.crypto.hash.sha2.Sha512.hash(self.inner_header.stream_key, &digest, .{});

    var chacha20 = ChaCha20.init(
        0,
        digest[0..32].*,
        digest[32..44].*,
    );

    const root__ = try parseRoot(root_.?, allocator, &chacha20);
    errdefer root__.deinit();

    return .{ .meta = meta_, .root = root__ };
}

fn parseRoot(elem: dishwasher.Document.Node.Element, allocator: Allocator, cipher: *ChaCha20) !Group {
    const curr_group = elem.elementByTagName("Group");
    if (curr_group == null) return error.RootGroupMissing;

    return try parseGroup(curr_group.?, allocator, cipher);
}

fn parseGroup(elem: dishwasher.Document.Node.Element, allocator: Allocator, cipher: *ChaCha20) !Group {
    var uuid = try fetchUuid(elem, "UUID", allocator);
    errdefer uuid = 0;

    const name = try fetchTagValue(elem, "Name", allocator);
    errdefer {
        std.crypto.utils.secureZero(u8, name);
        allocator.free(name);
    }

    const notes = try fetchTagValueNull(elem, "Notes", allocator);
    errdefer if (notes) |v| {
        std.crypto.utils.secureZero(u8, v);
        allocator.free(v);
    };

    var icon_id = try fetchNumTag(elem, "IconID", allocator);
    errdefer icon_id = 0;

    const times = elem.elementByTagName("Times");
    if (times == null) return error.TimesMissing;

    var last_modification_time = try fetchTimeTag(times.?, "LastModificationTime", allocator);
    errdefer last_modification_time = 0;

    var last_access_time = try fetchTimeTag(times.?, "LastAccessTime", allocator);
    errdefer last_access_time = 0;

    var creation_time = try fetchTimeTag(times.?, "CreationTime", allocator);
    errdefer creation_time = 0;

    var expiry_time = try fetchTimeTag(times.?, "ExpiryTime", allocator);
    errdefer expiry_time = 0;

    const expires = try fetchBool(times.?, "Expires", allocator);

    var usage_count = try fetchNumTag(times.?, "UsageCount", allocator);
    errdefer usage_count = 0;

    var location_changed = try fetchTimeTag(times.?, "LocationChanged", allocator);
    errdefer location_changed = 0;

    const is_expanded = try fetchBool(elem, "IsExpanded", allocator);

    const default_auto_type_sequence = try fetchTagValueNull(elem, "DefaultAutoTypeSequence", allocator);
    errdefer if (default_auto_type_sequence) |v| {
        std.crypto.utils.secureZero(u8, v);
        allocator.free(v);
    };

    const enable_auto_type = fetchBool(elem, "EnableAutoType", allocator) catch null;

    const enable_searching = fetchBool(elem, "EnableSearching", allocator) catch null;

    var last_top_visible_entry = try fetchUuid(elem, "LastTopVisibleEntry", allocator);
    errdefer last_top_visible_entry = 0;

    const previous_parent_group = fetchUuid(elem, "PreviousParentGroup", allocator) catch null;

    // Parse all entries

    const entries = try elem.elementsByTagNameAlloc(allocator, "Entry");
    defer allocator.free(entries);

    var entries_array = std.ArrayList(Entry).init(allocator);
    errdefer {
        for (entries_array.items) |item| item.deinit();
        entries_array.deinit();
    }

    for (entries) |entry| {
        try entries_array.append(try parseEntry(entry, allocator, cipher));
    }

    // Parse all groups

    const groups = try elem.elementsByTagNameAlloc(allocator, "Group");
    defer allocator.free(groups);

    var groups_array = std.ArrayList(Group).init(allocator);
    errdefer {
        for (groups_array.items) |item| item.deinit();
        groups_array.deinit();
    }

    for (groups) |group| {
        try groups_array.append(try parseGroup(group, allocator, cipher));
    }

    return .{
        .uuid = uuid,
        .name = name,
        .notes = notes,
        .icon_id = icon_id,
        .times = .{
            .last_modification_time = last_modification_time,
            .creation_time = creation_time,
            .last_access_time = last_access_time,
            .expiry_time = expiry_time,
            .expires = expires,
            .usage_count = usage_count,
            .location_changed = location_changed,
        },
        .is_expanded = is_expanded,
        .default_auto_type_sequence = default_auto_type_sequence,
        .enable_auto_type = enable_auto_type,
        .enable_searching = enable_searching,
        .last_top_visible_entry = last_top_visible_entry,
        .previous_parent_group = previous_parent_group,
        .entries = entries_array,
        .groups = groups_array,
        .allocator = allocator,
    };
}

fn parseIcon(elem: dishwasher.Document.Node.Element, allocator: Allocator) !Icon {
    return .{
        .uuid = try fetchUuid(elem, "UUID", allocator),
        .last_modification_time = try fetchTimeTag(elem, "LastModificationTime", allocator),
        .data = try fetchTagValue(elem, "Data", allocator),
    };
}

fn parseEntry(elem: dishwasher.Document.Node.Element, allocator: Allocator, cipher: *ChaCha20) !Entry {
    var uuid = try fetchUuid(elem, "UUID", allocator);
    errdefer uuid = 0;

    var icon_id = try fetchNumTag(elem, "IconID", allocator);
    errdefer icon_id = 0;

    const custom_icon_uuid = fetchUuid(elem, "CustomIconUUID", allocator) catch null;

    const foreground_color = try fetchTagValueNull(elem, "ForegroundColor", allocator);
    errdefer if (foreground_color) |v| {
        std.crypto.utils.secureZero(u8, v);
        allocator.free(v);
    };

    const background_color = try fetchTagValueNull(elem, "BackgroundColor", allocator);
    errdefer if (background_color) |v| {
        std.crypto.utils.secureZero(u8, v);
        allocator.free(v);
    };

    const override_url = try fetchTagValueNull(elem, "OverrideURL", allocator);
    errdefer if (override_url) |v| {
        std.crypto.utils.secureZero(u8, v);
        allocator.free(v);
    };

    const tags = try fetchTagValueNull(elem, "Tags", allocator);
    errdefer if (tags) |v| {
        std.crypto.utils.secureZero(u8, v);
        allocator.free(v);
    };

    const times = elem.elementByTagName("Times");
    if (times == null) return error.TimesMissing;

    var last_modification_time = try fetchTimeTag(times.?, "LastModificationTime", allocator);
    errdefer last_modification_time = 0;

    var last_access_time = try fetchTimeTag(times.?, "LastAccessTime", allocator);
    errdefer last_access_time = 0;

    var creation_time = try fetchTimeTag(times.?, "CreationTime", allocator);
    errdefer creation_time = 0;

    var expiry_time = try fetchTimeTag(times.?, "ExpiryTime", allocator);
    errdefer expiry_time = 0;

    const expires = try fetchBool(times.?, "Expires", allocator);

    var usage_count = try fetchNumTag(times.?, "UsageCount", allocator);
    errdefer usage_count = 0;

    var location_changed = try fetchTimeTag(times.?, "LocationChanged", allocator);
    errdefer location_changed = 0;

    var strings = std.ArrayList(KeyValue).init(allocator);
    errdefer {
        for (strings.items) |item| item.deinit(allocator);
        strings.deinit();
    }

    const strings_ = try elem.elementsByTagNameAlloc(allocator, "String");
    defer allocator.free(strings_);

    for (strings_) |kv| {
        const key = try fetchTagValue(kv, "Key", allocator);
        errdefer allocator.free(key);
        var value = try fetchTagValue(kv, "Value", allocator);
        errdefer allocator.free(value);
        var protected = false;

        // Deobfuscate value if "Protected = True"
        // Value is present because otherwise the try above would already have thrown an error.
        if (if (kv.elementByTagName("Value").?.attributeValueByName("Protected")) |bool_value| std.mem.eql(u8, "True", bool_value) else false) {
            const l = try std.base64.standard.Decoder.calcSizeForSlice(value);
            const value_ = try allocator.alloc(u8, l);
            errdefer allocator.free(value_);
            try std.base64.standard.Decoder.decode(value_, value);

            cipher.xor(value_);
            allocator.free(value);
            value = value_;

            protected = true;
        }

        try strings.append(KeyValue{
            .key = key,
            .value = value,
            .protected = protected,
        });
    }

    const auto_type = elem.elementByTagName("AutoType");
    var auto_type_: ?AutoType = null;
    errdefer if (auto_type_ != null and auto_type_.?.default_sequence != null)
        allocator.free(auto_type_.?.default_sequence.?);
    if (auto_type) |at| {
        const enabled = try fetchBool(at, "Enabled", allocator);
        const data_transfer_obfuscation = try fetchNumTag(at, "DataTransferObfuscation", allocator);

        const default_sequence = try fetchTagValueNull(at, "DefaultSequence", allocator);
        auto_type_ = .{
            .enabled = enabled,
            .data_transfer_obfuscation = data_transfer_obfuscation,
            .default_sequence = default_sequence,
        };
    }

    var history: ?std.ArrayList(Entry) = null;
    errdefer if (history) |h| {
        for (h.items) |item| item.deinit();
        h.deinit();
    };

    const hist = elem.elementByTagName("History");
    if (hist) |h| outer: {
        const entries = try h.elementsByTagNameAlloc(allocator, "Entry");
        defer allocator.free(entries);

        if (entries.len == 0) break :outer; // nothing to-do

        history = std.ArrayList(Entry).init(allocator);

        for (entries) |entry| {
            try history.?.append(try parseEntry(entry, allocator, cipher));
        }
    }

    return .{
        .uuid = uuid,
        .icon_id = icon_id,
        .custom_icon_uuid = custom_icon_uuid,
        .foreground_color = foreground_color,
        .background_color = background_color,
        .override_url = override_url,
        .tags = tags,
        .times = .{
            .last_modification_time = last_modification_time,
            .creation_time = creation_time,
            .last_access_time = last_access_time,
            .expiry_time = expiry_time,
            .expires = expires,
            .usage_count = usage_count,
            .location_changed = location_changed,
        },
        .strings = strings,
        .auto_type = auto_type_,
        .history = history,
        .allocator = allocator,
    };
}

fn parseMeta(elem: dishwasher.Document.Node.Element, allocator: Allocator) !Meta {
    const generator = try fetchTagValue(elem, "Generator", allocator);
    errdefer {
        std.crypto.utils.secureZero(u8, generator);
        allocator.free(generator);
    }

    const database_name = try fetchTagValue(elem, "DatabaseName", allocator);
    errdefer {
        std.crypto.utils.secureZero(u8, database_name);
        allocator.free(database_name);
    }

    var database_name_changed = try fetchTimeTag(elem, "DatabaseNameChanged", allocator);
    errdefer database_name_changed = 0;

    const database_description = try fetchTagValueNull(elem, "DatabaseDescription", allocator);
    errdefer if (database_description) |v| {
        std.crypto.utils.secureZero(u8, v);
        allocator.free(v);
    };

    var database_description_changed = try fetchTimeTag(elem, "DatabaseDescriptionChanged", allocator);
    errdefer database_description_changed = 0;

    const default_user_name = try fetchTagValueNull(elem, "DefaultUserName", allocator);
    errdefer if (default_user_name) |v| {
        std.crypto.utils.secureZero(u8, v);
        allocator.free(v);
    };

    var default_user_name_changed = try fetchTimeTag(elem, "DefaultUserNameChanged", allocator);
    errdefer default_user_name_changed = 0;

    var maintenance_history_days = try fetchNumTag(elem, "MaintenanceHistoryDays", allocator);
    errdefer maintenance_history_days = 0;

    const color = try fetchTagValueNull(elem, "Color", allocator);
    errdefer if (color) |v| {
        std.crypto.utils.secureZero(u8, v);
        allocator.free(v);
    };

    var master_key_changed = try fetchTimeTag(elem, "MasterKeyChanged", allocator);
    errdefer master_key_changed = 0;

    var master_key_change_rec = try fetchNumTag(elem, "MasterKeyChangeRec", allocator);
    errdefer master_key_change_rec = 0;

    var master_key_change_force = try fetchNumTag(elem, "MasterKeyChangeForce", allocator);
    errdefer master_key_change_force = 0;

    const protection = elem.elementByTagName("MemoryProtection");
    if (protection == null) return error.TagMissing;
    const protect_title = try fetchBool(protection.?, "ProtectTitle", allocator);
    const protect_user_name = try fetchBool(protection.?, "ProtectUserName", allocator);
    const protect_password = try fetchBool(protection.?, "ProtectPassword", allocator);
    const protect_url = try fetchBool(protection.?, "ProtectURL", allocator);
    const protect_notes = try fetchBool(protection.?, "ProtectNotes", allocator);

    var custom_icons: ?std.ArrayList(Icon) = null;
    errdefer {
        if (custom_icons) |icos| {
            for (icos.items) |ico| ico.deinit(allocator);
            icos.deinit();
        }
    }

    const custom_icons_ = elem.elementByTagName("CustomIcons");
    if (custom_icons_) |icos| outer: {
        const icons = try icos.elementsByTagNameAlloc(allocator, "Icon");
        defer allocator.free(icons);

        if (icons.len == 0) break :outer;

        custom_icons = std.ArrayList(Icon).init(allocator);

        for (icons) |icon| try custom_icons.?.append(try parseIcon(icon, allocator));
    }

    const recycle_bin_enabled = try fetchBool(elem, "RecycleBinEnabled", allocator);

    const recycle_bin_uuid = try fetchUuid(elem, "RecycleBinUUID", allocator);

    var recycle_bin_changed = try fetchTimeTag(elem, "RecycleBinChanged", allocator);
    errdefer recycle_bin_changed = 0;

    const entry_templates_group = try fetchUuid(elem, "EntryTemplatesGroup", allocator);

    var entry_templates_group_changed = try fetchTimeTag(elem, "EntryTemplatesGroupChanged", allocator);
    errdefer entry_templates_group_changed = 0;

    const last_selected_group = try fetchUuid(elem, "LastSelectedGroup", allocator);

    const last_top_visible_group = try fetchUuid(elem, "LastTopVisibleGroup", allocator);

    var history_max_items = try fetchNumTag(elem, "HistoryMaxItems", allocator);
    errdefer history_max_items = 0;

    var history_max_size = try fetchNumTag(elem, "HistoryMaxSize", allocator);
    errdefer history_max_size = 0;

    var settings_changed = try fetchTimeTag(elem, "SettingsChanged", allocator);
    errdefer settings_changed = 0;

    var custom_data = std.ArrayList(KeyValue).init(allocator);
    errdefer {
        for (custom_data.items) |item| item.deinit(allocator);
        custom_data.deinit();
    }

    const custom_data_ = elem.elementByTagName("CustomData");
    if (custom_data_) |cd| outer: {
        const pairs = cd.elementsByTagNameAlloc(allocator, "Item") catch break :outer;
        defer allocator.free(pairs);

        for (pairs) |kv| {
            const key = try fetchTagValue(kv, "Key", allocator);
            errdefer allocator.free(key);
            const value = try fetchTagValue(kv, "Value", allocator);
            errdefer allocator.free(value);

            try custom_data.append(KeyValue{ .key = key, .value = value });
        }
    }

    return Meta{
        .generator = generator,
        .database_name = database_name,
        .database_name_changed = database_name_changed,
        .database_description = database_description,
        .database_description_changed = database_description_changed,
        .default_user_name = default_user_name,
        .default_user_name_changed = default_user_name_changed,
        .maintenance_history_days = maintenance_history_days,
        .color = color,
        .master_key_changed = master_key_changed,
        .master_key_change_rec = master_key_change_rec,
        .master_key_change_force = master_key_change_force,
        .memory_protection = .{
            .protect_title = protect_title,
            .protect_user_name = protect_user_name,
            .protect_password = protect_password,
            .protect_url = protect_url,
            .protect_notes = protect_notes,
        },
        .custom_icons = custom_icons,
        .recycle_bin_enabled = recycle_bin_enabled,
        .recycle_bin_uuid = recycle_bin_uuid,
        .recycle_bin_changed = recycle_bin_changed,
        .entry_template_group = entry_templates_group,
        .entry_template_group_changed = entry_templates_group_changed,
        .last_selected_group = last_selected_group,
        .last_top_visible_group = last_top_visible_group,
        .history_max_items = history_max_items,
        .history_max_size = history_max_size,
        .settings_changed = settings_changed,
        .custom_data = custom_data,
        .allocator = allocator,
    };
}

fn fetchTagValue(elem: dishwasher.Document.Node.Element, name: []const u8, allocator: Allocator) ![]u8 {
    const v = if (elem.elementByTagName(name)) |v| v else {
        //std.log.err("{s} tag missing", .{name});
        return error.TagMissing;
    };
    return @constCast(try v.textAlloc(allocator));
}

fn fetchTagValueNull(elem: dishwasher.Document.Node.Element, name: []const u8, allocator: Allocator) !?[]u8 {
    const v = if (elem.elementByTagName(name)) |v| v else return null;
    return @constCast(try v.textAlloc(allocator));
}

/// Fetch time in seconds
fn fetchTimeTag(elem: dishwasher.Document.Node.Element, name: []const u8, allocator: Allocator) !i64 {
    const time = try fetchTagValue(elem, name, allocator);
    defer allocator.free(time);
    const l = try std.base64.standard.Decoder.calcSizeForSlice(time);
    const dnc = try allocator.alloc(u8, l);
    defer allocator.free(dnc);
    try std.base64.standard.Decoder.decode(dnc, time);
    const t = std.mem.readInt(u64, dnc[0..8], .little);
    // We have to switch from 0001-01-01 00:00 UTC to EPOCH
    //t -= TIME_DIFF_KDBX_EPOCH_IN_SEC;
    return @intCast(t);
}

fn fetchNumTag(elem: dishwasher.Document.Node.Element, name: []const u8, allocator: Allocator) !i64 {
    const value = try fetchTagValue(elem, name, allocator);
    defer allocator.free(value);
    return try std.fmt.parseInt(i64, value, 10);
}

fn fetchBool(elem: dishwasher.Document.Node.Element, name: []const u8, allocator: Allocator) !bool {
    const value = try fetchTagValue(elem, name, allocator);
    defer allocator.free(value);
    return if (std.mem.eql(u8, "False", value))
        false
    else if (std.mem.eql(u8, "True", value))
        true
    else
        error.NotABool;
}

fn fetchUuid(elem: dishwasher.Document.Node.Element, name: []const u8, allocator: Allocator) !Uuid.Uuid {
    const time = try fetchTagValue(elem, name, allocator);
    defer allocator.free(time);
    const l = try std.base64.standard.Decoder.calcSizeForSlice(time);
    if (l != 16) return error.UnexpectedUuidLength;
    const dnc = try allocator.alloc(u8, l);
    defer allocator.free(dnc);
    try std.base64.standard.Decoder.decode(dnc, time);
    return std.mem.readInt(Uuid.Uuid, dnc[0..16], .little);
}

// ------------------------------ Serialize -------------------------------

pub fn writeBool(out: anytype, v: bool) !void {
    try out.writeAll(if (v) "True" else "False");
}

pub fn writeI64(out: anytype, v: i64, allocator: Allocator) !void {
    var v_: [8]u8 = undefined;
    std.mem.writeInt(i64, &v_, v, .little);
    try writeBase64(out, v_[0..], allocator);
}

pub fn writeUuid(out: anytype, uuid: Uuid.Uuid, allocator: Allocator) !void {
    var uuid_: [16]u8 = undefined;
    std.mem.writeInt(Uuid.Uuid, &uuid_, uuid, .little);
    try writeBase64(out, uuid_[0..], allocator);
}

pub fn writeBase64(out: anytype, in: []const u8, allocator: Allocator) !void {
    const l = std.base64.standard.Encoder.calcSize(in.len);
    const m = try allocator.alloc(u8, l);
    defer {
        std.crypto.utils.secureZero(u8, m);
        allocator.free(m);
    }
    _ = std.base64.standard.Encoder.encode(m, in);
    try out.writeAll(m);
}

test "write uuid #1" {
    // D/LLsWnVT9q7aNpnKR3LBw==
    const id = try Uuid.urn.deserialize("0ff2cbb1-69d5-4fda-bb68-da67291dcb07");
    var arr = std.ArrayList(u8).init(std.testing.allocator);
    defer arr.deinit();
    try writeUuid(arr.writer(), id, std.testing.allocator);
    try std.testing.expectEqualSlices(u8, "D/LLsWnVT9q7aNpnKR3LBw==", arr.items);
}
