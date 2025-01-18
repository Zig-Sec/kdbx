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

    try database.body.root.addGroup(group1);

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
}
