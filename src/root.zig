const std = @import("std");

pub const Database = @import("Database.zig");

pub const v4 = @import("v4.zig");
pub const Entry = v4.Entry;
pub const Group = v4.Group;

pub const pem = @import("pem.zig");

pub const DatabaseKey = @import("DatabaseKey.zig");

test {
    _ = pem;
    _ = @import("tests.zig");
}

test "v4 tests" {
    _ = Database;
    _ = v4;
}

test "Database test #1" {
    const allocator = std.testing.allocator;

    {
        var database = try Database.new(.{
            .allocator = allocator,
        });
        defer database.deinit();
    }
}
