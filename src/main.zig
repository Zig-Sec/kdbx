const std = @import("std");
const kdbx = @import("kdbx");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

pub fn main() !void {
    var database = try kdbx.Database.new(.{
        .allocator = allocator,
    });
    defer database.deinit();

    var group1 = try kdbx.Group.new("Demo group", allocator);
    errdefer group1.deinit();

    var entry1 = kdbx.Entry.new(allocator);
    try entry1.set("Title", "Demo Entry", false);
    try entry1.set("UserName", "max", false);
    try entry1.set("Password", "supersecret", true);
    errdefer entry1.deinit();
    try group1.addEntry(entry1);

    var entry2 = kdbx.Entry.new(allocator);
    try entry2.set("Title", "Demo Entry 2", false);
    try entry2.set("UserName", "peter", false);
    try entry2.set("Password", "1234@#", true);
    errdefer entry2.deinit();
    try group1.addEntry(entry2);

    try database.body.root.addGroup(group1);

    var entry3 = kdbx.Entry.new(allocator);
    try entry3.set("Title", "Demo Entry 3", false);
    try entry3.set("UserName", "fiona", false);
    try entry3.set("Password", "foobar", true);
    errdefer entry3.deinit();
    try database.body.root.addEntry(entry3);

    const db_key = kdbx.DatabaseKey{
        .password = try allocator.dupe(u8, "1234"),
        .allocator = allocator,
    };
    defer db_key.deinit();

    const raw = try database.save(
        db_key,
        allocator,
    );
    defer allocator.free(raw);

    var file = try std.fs.cwd().createFile("db.kdbx", .{});
    defer file.close();

    try file.writeAll(raw);

    // --------------------------------------------

    var fbs = std.io.fixedBufferStream(raw);
    const reader = fbs.reader();

    //std.debug.print("{s}", .{std.fmt.fmtSliceHexLower(raw)});

    var database2 = kdbx.Database.open(reader, .{
        .allocator = allocator,
        .key = db_key,
    }) catch |e| {
        std.log.err("unable to decrypt database {any}", .{e});
        return;
    };
    defer database2.deinit();

    var root_iterator = database2.body.root.iterate(.entry);
    while (root_iterator.next()) |node| {
        switch (node) {
            .entry => |e| std.debug.print("{s}\n", .{e.strings.items[0].value}),
            .group => {},
        }
    }
}
