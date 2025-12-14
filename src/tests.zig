const std = @import("std");
const kdbx = @import("root.zig");

const db2 = @embedFile("static/TestDb2.kdbx");

test "access group using path #1" {
    const allocator = std.testing.allocator;
    var pw: [6]u8 = "foobar".*;

    var fbs = std.Io.Reader.fixed(db2);
    const reader = &fbs;

    const db_key = kdbx.DatabaseKey{
        .password = &pw,
    };

    var database = try kdbx.Database.open(reader, .{
        .allocator = allocator,
        .key = db_key,
    });
    defer database.deinit();

    var g = database.getGroup("/Work/Project One");
    try std.testing.expect(g != null);

    const e = g.?.getEntryByValue("Title", "Server Secret");
    try std.testing.expect(e != null);

    try std.testing.expectEqualStrings("fx12qq", e.?.get("UserName").?);
    try std.testing.expectEqualStrings("21c0be125544bd4f1e8c3503294ef4fb40bf212d04a7ab4ecfe2d46442585febd115385eb48d45ca34e7726a5762b0ea2fe2271130dce00f83ad5c8620689b0c1ca2fa9a174dced7a9a68a0b3caec10d", e.?.get("Key").?);
}
