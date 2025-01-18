const std = @import("std");
const kdbx = @import("kdbx");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

pub fn main() !void {
    const database = try kdbx.newDatabase(.{
        .password = "1234",
        .allocator = allocator,
    });
    defer allocator.free(database);

    var file = try std.fs.cwd().createFile("foo.kdbx", .{});
    defer file.close();

    try file.writeAll(database);

    // ------------------------------------

    var fbs = std.io.fixedBufferStream(database);
    const reader = fbs.reader();

    const header = try kdbx.Header.readAlloc(reader, allocator);
    defer header.deinit();

    var keys = try header.deriveKeys("1234", null, null);
    defer keys.deinit();
    try header.checkMac(&keys);

    var body = try kdbx.Body.readAlloc(reader, &header, &keys, allocator);
    defer body.deinit();

    //std.debug.print("{s}\n", .{body.xml});

    const body_xml = try body.getXml(allocator);
    defer body_xml.deinit();
}
