const std = @import("std");
const kdbx = @import("kdbx");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

pub fn main() !void {
    var database = try kdbx.Database.new(.{
        .allocator = allocator,
    });
    defer database.deinit();

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
