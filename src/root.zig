pub const Database = @import("Database.zig");

pub const v4 = @import("v4.zig");
pub const Entry = v4.Entry;

pub const DatabaseKey = @import("DatabaseKey.zig");

test "v4 tests" {
    _ = Database;
    _ = v4;
}
