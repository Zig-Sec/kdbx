const std = @import("std");
const Allocator = std.mem.Allocator;

const Uuid = @import("uuid");

const dishwasher = @import("dishwasher");

const ChaCha20 = @import("../chacha.zig").ChaCha20;

const v4 = @import("../v4.zig");
const Body = v4.Body;

const misc = @import("../misc.zig");
const currTime = misc.currTime;

const pem = @import("../pem.zig");

const XML_INDENT = 2;

const TIME_DIFF_KDBX_EPOCH_IN_SEC = 62135600008;

pub const XML = struct {
    meta: Meta,
    root: Group,

    pub fn deinit(self: *const @This()) void {
        self.meta.deinit();
        self.root.deinit();
    }

    pub fn toXml(
        self: *const @This(),
        out: anytype,
        cipher: *ChaCha20,
    ) !void {
        try out.writeAll("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
        try out.writeAll("<KeePassFile>\n");
        {
            try self.meta.toXml(out, 1);

            for (0..1 * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("<Root>\n");
            {
                try self.root.toXml(out, 2, cipher);

                for (0..2 * XML_INDENT) |_| try out.writeByte(' ');
                try out.writeAll("<DeletedObjects/>\n");
            }
            for (0..1 * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("</Root>\n");
        }
        try out.writeAll("</KeePassFile>\n");
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
        protect_title: bool = false,
        protect_user_name: bool = false,
        protect_password: bool = true,
        protect_url: bool = false,
        protect_notes: bool = false,
    } = .{},
    custom_icons: ?std.ArrayList(Icon) = null,
    recycle_bin_enabled: bool = true,
    recycle_bin_uuid: Uuid.Uuid = 0,
    recycle_bin_changed: i64,
    entry_template_group: Uuid.Uuid = 0,
    entry_template_group_changed: i64,
    last_selected_group: Uuid.Uuid = 0,
    last_top_visible_group: Uuid.Uuid = 0,
    history_max_items: i64 = 10,
    history_max_size: i64 = 6291456,
    settings_changed: i64,
    custom_data: std.ArrayList(KeyValue),
    allocator: Allocator,

    pub fn toXml(
        self: *const @This(),
        out: anytype,
        level: usize,
    ) !void {
        for (0..level * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<Meta>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<Generator>");
        try out.writeAll(self.generator);
        try out.writeAll("</Generator>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<DatabaseName>");
        try out.writeAll(self.database_name);
        try out.writeAll("</DatabaseName>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<DatabaseNameChanged>");
        try writeI64(out, self.database_name_changed, self.allocator);
        try out.writeAll("</DatabaseNameChanged>\n");

        if (self.database_description) |desc| {
            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("<DatabaseDescription>");
            try out.writeAll(desc);
            try out.writeAll("</DatabaseDescription>\n");
        } else {
            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("<DatabaseDescription/>\n");
        }

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<DatabaseDescriptionChanged>");
        try writeI64(out, self.database_description_changed, self.allocator);
        try out.writeAll("</DatabaseDescriptionChanged>\n");

        if (self.default_user_name) |uname| {
            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("<DefaultUserName>");
            try out.writeAll(uname);
            try out.writeAll("</DefaultUserName>\n");
        } else {
            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("<DefaultUserName/>\n");
        }

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<DefaultUserNameChanged>");
        try writeI64(out, self.default_user_name_changed, self.allocator);
        try out.writeAll("</DefaultUserNameChanged>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<MaintenanceHistoryDays>");
        try out.print("{d}", .{self.maintenance_history_days});
        try out.writeAll("</MaintenanceHistoryDays>\n");

        if (self.color) |color| {
            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("<Color>");
            try out.writeAll(color);
            try out.writeAll("</Color>\n");
        } else {
            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("<Color/>\n");
        }

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<MasterKeyChanged>");
        try writeI64(out, self.master_key_changed, self.allocator);
        try out.writeAll("</MasterKeyChanged>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<MasterKeyChangeRec>");
        try out.print("{d}", .{self.master_key_change_rec});
        try out.writeAll("</MasterKeyChangeRec>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<MasterKeyChangeForce>");
        try out.print("{d}", .{self.master_key_change_force});
        try out.writeAll("</MasterKeyChangeForce>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<MemoryProtection>\n");

        for (0..(level + 2) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<ProtectTitle>");
        try out.print("{s}", .{if (self.memory_protection.protect_title) "True" else "False"});
        try out.writeAll("</ProtectTitle>\n");

        for (0..(level + 2) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<ProtectUserName>");
        try out.print("{s}", .{if (self.memory_protection.protect_user_name) "True" else "False"});
        try out.writeAll("</ProtectUserName>\n");

        for (0..(level + 2) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<ProtectPassword>");
        try out.print("{s}", .{if (self.memory_protection.protect_password) "True" else "False"});
        try out.writeAll("</ProtectPassword>\n");

        for (0..(level + 2) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<ProtectURL>");
        try out.print("{s}", .{if (self.memory_protection.protect_url) "True" else "False"});
        try out.writeAll("</ProtectURL>\n");

        for (0..(level + 2) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<ProtectNotes>");
        try out.print("{s}", .{if (self.memory_protection.protect_notes) "True" else "False"});
        try out.writeAll("</ProtectNotes>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("</MemoryProtection>\n");

        if (self.custom_icons) |icons| {
            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("<CustomIcons>\n");

            for (icons.items) |icon| try icon.toXml(
                out,
                level + 2,
                self.allocator,
            );

            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("</CustomIcons>\n");
        } else {
            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("<CustomIcons/>\n");
        }

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<RecycleBinEnabled>");
        try out.print("{s}", .{if (self.recycle_bin_enabled) "True" else "False"});
        try out.writeAll("</RecycleBinEnabled>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<RecycleBinUUID>");
        try writeUuid(out, self.recycle_bin_uuid, self.allocator);
        try out.writeAll("</RecycleBinUUID>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<RecycleBinChanged>");
        try writeI64(out, self.recycle_bin_changed, self.allocator);
        try out.writeAll("</RecycleBinChanged>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<EntryTemplatesGroup>");
        try writeUuid(out, self.entry_template_group, self.allocator);
        try out.writeAll("</EntryTemplatesGroup>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<EntryTemplatesGroupChanged>");
        try writeI64(out, self.entry_template_group_changed, self.allocator);
        try out.writeAll("</EntryTemplatesGroupChanged>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<LastSelectedGroup>");
        try writeUuid(out, self.last_selected_group, self.allocator);
        try out.writeAll("</LastSelectedGroup>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<LastTopVisibleGroup>");
        try writeUuid(out, self.last_top_visible_group, self.allocator);
        try out.writeAll("</LastTopVisibleGroup>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<HistoryMaxItems>");
        try out.print("{d}", .{self.history_max_items});
        try out.writeAll("</HistoryMaxItems>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<HistoryMaxSize>");
        try out.print("{d}", .{self.history_max_size});
        try out.writeAll("</HistoryMaxSize>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<SettingsChanged>");
        try writeI64(out, self.settings_changed, self.allocator);
        try out.writeAll("</SettingsChanged>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<CustomData>\n");

        {
            for (self.custom_data.items) |data| {
                for (0..(level + 2) * XML_INDENT) |_| try out.writeByte(' ');
                try out.writeAll("<Item>\n");

                for (0..(level + 3) * XML_INDENT) |_| try out.writeByte(' ');
                try out.writeAll("<Key>");
                try out.writeAll(data.key);
                try out.writeAll("</Key>\n");

                for (0..(level + 3) * XML_INDENT) |_| try out.writeByte(' ');
                try out.writeAll("<Value>");
                try out.writeAll(data.value);
                try out.writeAll("</Value>\n");

                if (data.last_modification_time) |t| {
                    for (0..(level + 3) * XML_INDENT) |_| try out.writeByte(' ');
                    try out.writeAll("<LastModificationTime>");
                    try writeI64(out, t, self.allocator);
                    try out.writeAll("</LastModificationTime>\n");
                }

                for (0..(level + 2) * XML_INDENT) |_| try out.writeByte(' ');
                try out.writeAll("</Item>\n");
            }
        }

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("</CustomData>\n");

        for (0..level * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("</Meta>\n");
    }

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

    pub fn toXml(
        self: *const @This(),
        out: anytype,
        level: usize,
        allocator: Allocator,
    ) !void {
        for (0..level * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<Icon>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<UUID>");
        try writeUuid(out, self.uuid, allocator);
        try out.writeAll("</UUID>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<LastModificationTime>");
        try writeI64(out, self.last_modification_time, allocator);
        try out.writeAll("</LastModificationTime>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<Data>");
        try writeBase64(out, self.data, allocator);
        try out.writeAll("</Data>\n");

        for (0..level * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("</Icon>\n");
    }

    pub fn deinit(self: *const @This(), allocator: Allocator) void {
        std.crypto.utils.secureZero(u8, self.data);
        allocator.free(self.data);
    }
};

pub const KeyValue = struct {
    key: []u8,
    value: []u8,
    last_modification_time: ?i64 = null,
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
                try writeBase64(out, m, allocator);
            } else {
                try out.writeAll("<Value>");
                try out.print("{s}", .{self.value});
            }
            try out.writeAll("</Value>\n");
        } else {
            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("<Value/>\n");
        }

        if (self.last_modification_time) |time| {
            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("<LastModificationTime>");
            try writeI64(out, time, allocator);
            try out.writeAll("</LastModificationTime>\n");
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

    pub const IteratorTag = enum { entry, group };
    pub const Iterator = union(IteratorTag) {
        entry: struct {
            grp: *Group,
            idx: usize = 0,
        },
        group: struct {
            grp: *Group,
            idx: usize = 0,
        },

        pub const Result = union(IteratorTag) {
            entry: *Entry,
            group: *Group,
        };

        pub fn next(self: *@This()) ?Result {
            return switch (self.*) {
                .entry => |*e| blk: {
                    if (e.idx >= e.grp.entries.items.len) return null;
                    defer e.idx += 1;
                    break :blk .{ .entry = &e.grp.entries.items[e.idx] };
                },
                .group => |*g| blk: {
                    if (g.idx >= g.grp.groups.items.len) return null;
                    defer g.idx += 1;
                    break :blk .{ .group = &g.grp.groups.items[g.idx] };
                },
            };
        }
    };

    pub fn iterate(self: *@This(), @"type": IteratorTag) Iterator {
        return switch (@"type") {
            .entry => .{ .entry = .{ .grp = self } },
            .group => .{ .group = .{ .grp = self } },
        };
    }

    /// This will remove the entry with the given UUID from the group
    /// if it exists.
    ///
    /// The function returns the removed Entry. It is the responibility
    /// of the caller to `deinit` the Entry as soon as it is no longer
    /// needed.
    pub fn removeEntryByUuid(self: *@This(), uuid: Uuid.Uuid) ?Entry {
        for (0..self.entries.items.len) |i| {
            if (self.entries.items[i].uuid == uuid) {
                return self.entries.swapRemove(i);
            }
        }

        return null;
    }

    /// This will remove the nested group with the given UUID from the group
    /// if it exists.
    ///
    /// The function returns the removed Group. It is the responibility
    /// of the caller to `deinit` the Group and all its children as soon
    /// as it is no longer needed.
    pub fn removeGroupByUuid(self: *@This(), uuid: Uuid.Uuid) ?Group {
        for (0..self.groups.items.len) |i| {
            if (self.groups.items[i].uuid == uuid) {
                return self.groups.swapRemove(i);
            }
        }

        return null;
    }

    pub fn getEntryById(self: *@This(), uuid: Uuid.Uuid) ?*Entry {
        for (0..self.entries.items.len) |i| {
            if (self.entries.items[i].uuid == uuid) {
                return &self.entries.items[i];
            }
        }

        return null;
    }

    pub fn getGroupByName(self: *@This(), name: []const u8) ?*Group {
        for (0..self.groups.items.len) |i| {
            if (std.mem.eql(u8, self.groups.items[i].name, name)) {
                return &self.groups.items[i];
            }
        }

        return null;
    }

    pub fn addEntry(self: *@This(), entry: Entry) !void {
        for (0..self.entries.items.len) |i| {
            if (self.entries.items[i].uuid == entry.uuid)
                return error.EntryAlreadyExists;
        }

        try self.entries.append(entry);
    }

    pub fn createEntry(self: *@This()) !*Entry {
        try self.entries.append(Entry.new(self.allocator));
        return &self.entries.items[self.entries.items.len - 1];
    }

    pub fn addGroup(self: *@This(), group: Group) !void {
        for (0..self.groups.items.len) |i| {
            if (self.groups.items[i].uuid == group.uuid)
                return error.GroupAlreadyExists;
        }

        try self.groups.append(group);
    }

    pub fn createGroup(self: *@This(), name: []const u8) !*@This() {
        try self.groups.append(try Group.new(name, self.allocator));
        return &self.groups.items[self.groups.items.len - 1];
    }

    pub fn new(name: []const u8, allocator: Allocator) !@This() {
        return .{
            .name = try allocator.dupe(u8, name),
            .uuid = Uuid.v4.new(),
            .icon_id = 48,
            .times = Times.new(),
            .entries = std.ArrayList(Entry).init(allocator),
            .groups = std.ArrayList(Group).init(allocator),
            .last_top_visible_entry = 0,
            .allocator = allocator,
        };
    }

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
        try writeUuid(out, self.uuid, self.allocator);
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
        try writeUuid(
            out,
            self.last_top_visible_entry,
            self.allocator,
        );
        try out.writeAll("</LastTopVisibleEntry>\n");

        if (self.previous_parent_group) |ppg| {
            for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
            try out.writeAll("<PreviousParentGroup>");
            try writeUuid(
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

    pub fn new(allocator: Allocator) @This() {
        return .{
            .uuid = Uuid.v4.new(),
            .icon_id = 0,
            .times = Times.new(),
            .strings = std.ArrayList(KeyValue).init(allocator),
            .allocator = allocator,
        };
    }

    /// Create a new passkey compatible with KeePassXC.
    ///
    /// Supported signature schemes:
    /// * ES256 (ECDSA-P256-SHA256)
    pub fn newKeePassXCPasskey(
        allocator: Allocator,
        relying_party: []const u8,
        user_name: []const u8,
        user_id: []const u8,
        signature_scheme: []const u8,
    ) !@This() {
        var e = new(allocator);
        errdefer e.deinit();

        const pem_key = if (std.mem.eql(u8, "ES256", signature_scheme)) blk: {
            const es256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
            const kp = es256.KeyPair.generate();
            break :blk try pem.pemFromKey(kp, allocator);
        } else {
            return error.InvalidSignatureScheme;
        };
        defer {
            std.crypto.secureZero(u8, pem_key);
            allocator.free(pem_key);
        }

        try e.setKeePassXCPasskeyValues(
            relying_party,
            user_name,
            user_id,
            pem_key,
        );

        try e.set("URL", relying_party, false);
        try e.set("UserName", user_name, false);
        e.tags = try e.allocator.dupe(u8, "Passkey");

        return e;
    }

    pub fn setKeePassXCPasskeyValues(
        self: *@This(),
        relying_party: []const u8,
        user_name: []const u8,
        user_id: []const u8,
        pem_key: []const u8,
    ) !void {
        // The uuid of the entry is also the credential id of the passkey
        try self.set("KPEX_PASSKEY_CREDENTIAL_ID", Uuid.urn.serialize(self.uuid)[0..], true);

        try self.set("KPEX_PASSKEY_RELYING_PARTY", relying_party, true);
        try self.set("KPEX_PASSKEY_USERNAME", user_name, true);
        try self.set("KPEX_PASSKEY_USER_HANDLE", user_id, true);
        try self.set("KPEX_PASSKEY_PRIVATE_KEY_PEM", pem_key, true);
    }

    /// Check if the given entry is a valid KeePassXC passkey.
    ///
    /// This will also return `false` if the PEM key is not supported
    /// by this module. One reason could be that the cipher is not supported.
    pub fn isValidKeePassXCPasskey(self: *const @This()) bool {
        // Check that a valid key is present in PEM format
        const pem_key = self.get("KPEX_PASSKEY_PRIVATE_KEY_PEM");
        if (pem_key == null) return false;
        _ = pem.asymmetricKeyPairFromPem(pem_key.?, self.allocator) catch return false;

        if (self.get("KPEX_PASSKEY_CREDENTIAL_ID") == null) return false;
        if (self.get("KPEX_PASSKEY_RELYING_PARTY") == null) return false;
        if (self.get("KPEX_PASSKEY_USERNAME") == null) return false;
        if (self.get("KPEX_PASSKEY_USER_HANDLE") == null) return false;

        return true;
    }

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
        try writeUuid(out, self.uuid, self.allocator);
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

    pub fn new() @This() {
        const curr = currTime();
        return .{
            .last_modification_time = curr,
            .creation_time = curr,
            .last_access_time = curr,
            .expiry_time = curr,
            .expires = false,
            .usage_count = 0,
            .location_changed = curr,
        };
    }

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
        try writeI64(out, self.last_modification_time, allocator);
        try out.writeAll("</LastModificationTime>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<CreationTime>");
        try writeI64(out, self.creation_time, allocator);
        try out.writeAll("</CreationTime>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<LastAccessTime>");
        try writeI64(out, self.last_access_time, allocator);
        try out.writeAll("</LastAccessTime>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<ExpiryTime>");
        try writeI64(out, self.expiry_time, allocator);
        try out.writeAll("</ExpiryTime>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<Expires>");
        try writeBool(out, self.expires);
        try out.writeAll("</Expires>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<UsageCount>");
        try out.print("{d}", .{self.usage_count});
        try out.writeAll("</UsageCount>\n");

        for (0..(level + 1) * XML_INDENT) |_| try out.writeByte(' ');
        try out.writeAll("<LocationChanged>");
        try writeI64(out, self.location_changed, allocator);
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
        try writeBool(out, self.enabled);
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

pub fn parseXml(self: *const Body, allocator: Allocator) !XML {
    const tree = try dishwasher.parse.fromSlice(allocator, self.xml);
    defer tree.deinit();

    const file = tree.tree.elementByTagName("KeePassFile");
    if (file == null) return error.KeePassFileTagMissing;
    if (file.?.tree == null) return error.NoChildren;

    const meta = file.?.tree.?.elementByTagName("Meta");
    if (meta == null) return error.MetaTagMissing;

    const meta_ = try parseMeta(meta.?, allocator);
    errdefer meta_.deinit();

    const root_ = file.?.tree.?.elementByTagName("Root");
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

fn parseRoot(elem: dishwasher.parse.Tree.Node.Elem, allocator: Allocator, cipher: *ChaCha20) !Group {
    if (elem.tree == null) return error.NoChildren;

    const curr_group = elem.tree.?.elementByTagName("Group");
    if (curr_group == null) return error.RootGroupMissing;

    return try parseGroup(curr_group.?, allocator, cipher);
}

fn parseGroup(elem: dishwasher.parse.Tree.Node.Elem, allocator: Allocator, cipher: *ChaCha20) !Group {
    if (elem.tree == null) return error.NoChildren;

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

    const times = elem.tree.?.elementByTagName("Times");
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

    const entries = try elem.tree.?.elementsByTagNameAlloc(allocator, "Entry");
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

    const groups = try elem.tree.?.elementsByTagNameAlloc(allocator, "Group");
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

fn parseIcon(elem: dishwasher.parse.Tree.Node.Elem, allocator: Allocator) !Icon {
    return .{
        .uuid = try fetchUuid(elem, "UUID", allocator),
        .last_modification_time = try fetchTimeTag(elem, "LastModificationTime", allocator),
        .data = try fetchTagValue(elem, "Data", allocator),
    };
}

fn parseEntry(elem: dishwasher.parse.Tree.Node.Elem, allocator: Allocator, cipher: *ChaCha20) !Entry {
    if (elem.tree == null) return error.NoChildren;

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

    if (elem.tree == null) return error.NoChildren;
    const times = elem.tree.?.elementByTagName("Times");
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

    const strings_ = try elem.tree.?.elementsByTagNameAlloc(allocator, "String");
    defer allocator.free(strings_);

    for (strings_) |kv| {
        if (kv.tree == null) continue;

        const key = try fetchTagValue(kv, "Key", allocator);
        errdefer allocator.free(key);
        var value = try fetchTagValue(kv, "Value", allocator);
        errdefer allocator.free(value);
        var protected = false;

        // Deobfuscate value if "Protected = True"
        // Value is present because otherwise the try above would already have thrown an error.
        if (if (kv.tree.?.elementByTagName("Value").?.attributeValueByName("Protected")) |bool_value| std.mem.eql(u8, "True", bool_value) else false) {
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

    const auto_type = elem.tree.?.elementByTagName("AutoType");
    var auto_type_: ?AutoType = null;
    errdefer if (auto_type_ != null and auto_type_.?.default_sequence != null)
        allocator.free(auto_type_.?.default_sequence.?);
    if (auto_type) |at| {
        const enabled = fetchBool(at, "Enabled", allocator) catch null;
        const data_transfer_obfuscation = fetchNumTag(at, "DataTransferObfuscation", allocator) catch null;

        const default_sequence = fetchTagValueNull(at, "DefaultSequence", allocator) catch null;

        if (enabled != null and data_transfer_obfuscation != null or default_sequence != null) {
            auto_type_ = .{
                .enabled = enabled.?,
                .data_transfer_obfuscation = data_transfer_obfuscation.?,
                .default_sequence = default_sequence.?,
            };
        }
    }

    var history: ?std.ArrayList(Entry) = null;
    errdefer if (history) |h| {
        for (h.items) |item| item.deinit();
        h.deinit();
    };

    const hist = elem.tree.?.elementByTagName("History");
    if (hist) |h| outer: {
        if (h.tree == null) break :outer;

        const entries = try h.tree.?.elementsByTagNameAlloc(allocator, "Entry");
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

fn parseMeta(elem: dishwasher.parse.Tree.Node.Elem, allocator: Allocator) !Meta {
    if (elem.tree == null) return error.NoChildren;

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

    const protection = elem.tree.?.elementByTagName("MemoryProtection");
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

    const custom_icons_ = elem.tree.?.elementByTagName("CustomIcons");
    if (custom_icons_) |icos| outer: {
        if (icos.tree == null) break :outer;

        const icons = try icos.tree.?.elementsByTagNameAlloc(allocator, "Icon");
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

    const custom_data_ = elem.tree.?.elementByTagName("CustomData");
    if (custom_data_) |cd| outer: {
        if (cd.tree == null) break :outer;

        const pairs = cd.tree.?.elementsByTagNameAlloc(allocator, "Item") catch break :outer;
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

fn fetchTagValue(elem: dishwasher.parse.Tree.Node.Elem, name: []const u8, allocator: Allocator) ![]u8 {
    if (elem.tree == null) return error.NoChildren;

    const v = if (elem.tree.?.elementByTagName(name)) |v| v else {
        //std.log.err("{s} tag missing", .{name});
        return error.TagMissing;
    };

    return if (v.tree) |t| @constCast(try t.concatTextAlloc(allocator)) else try allocator.dupe(u8, "");
}

fn fetchTagValueNull(elem: dishwasher.parse.Tree.Node.Elem, name: []const u8, allocator: Allocator) !?[]u8 {
    if (elem.tree == null) return error.NoChildren;

    const v = if (elem.tree.?.elementByTagName(name)) |v| v else return null;

    return if (v.tree) |t| @constCast(try t.concatTextAlloc(allocator)) else try allocator.dupe(u8, "");
}

/// Fetch time in seconds
fn fetchTimeTag(elem: dishwasher.parse.Tree.Node.Elem, name: []const u8, allocator: Allocator) !i64 {
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

fn fetchNumTag(elem: dishwasher.parse.Tree.Node.Elem, name: []const u8, allocator: Allocator) !i64 {
    const value = try fetchTagValue(elem, name, allocator);
    defer allocator.free(value);
    return try std.fmt.parseInt(i64, value, 10);
}

fn fetchBool(elem: dishwasher.parse.Tree.Node.Elem, name: []const u8, allocator: Allocator) !bool {
    const value = try fetchTagValue(elem, name, allocator);
    defer allocator.free(value);
    return if (std.mem.eql(u8, "False", value))
        false
    else if (std.mem.eql(u8, "True", value))
        true
    else
        error.NotABool;
}

fn fetchUuid(elem: dishwasher.parse.Tree.Node.Elem, name: []const u8, allocator: Allocator) !Uuid.Uuid {
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
