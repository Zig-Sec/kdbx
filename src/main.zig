const std = @import("std");
const kdbx = @import("kdbx");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

pub fn main() !void {
    const database = try kdbx.Database.newDatabase(.{
        .password = "1234",
        .allocator = allocator,
    });
    defer allocator.free(database);

    var file = try std.fs.cwd().createFile("foo.kdbx", .{});
    defer file.close();

    try file.writeAll(database);
}
