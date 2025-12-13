const std = @import("std");
const kdbx = @import("kdbx");

const ENOENT: c_int = 2; // No such file or directory
const EIO: c_int = 5; // Input/output error
const ENOMEM: c_int = 12; // Cannot allocate memory
const EACCES: c_int = 13; // Permission denied

pub export fn kdbx_open_with_password(
    db: **anyopaque,
    path: [*c]u8,
    path_len: usize,
    password: [*c]u8,
    password_len: usize,
) c_int {
    const path_ = path[0..path_len];
    const password_ = password[0..password_len];

    std.debug.print("{s}\n", .{path_});
    std.debug.print("{s}\n", .{password_});

    var f = std.fs.cwd().openFile(
        path_,
        .{},
    ) catch {
        return ENOENT;
    };
    defer f.close();

    var buffer: [1024]u8 = undefined;
    var reader = f.reader(&buffer);

    const key = kdbx.DatabaseKey{
        .password = password_,
    };

    const database = kdbx.Database.open(&reader.interface, .{
        .allocator = std.heap.c_allocator,
        .key = key,
    }) catch {
        return EACCES;
    };

    const db_ = std.heap.c_allocator.create(kdbx.Database) catch {
        return ENOMEM;
    };
    db_.* = database;

    db.* = @as(*anyopaque, @ptrCast(db_));
    return 0;
}

pub export fn kdbx_close(
    db: *anyopaque,
) c_int {
    var db_: *kdbx.Database = @ptrCast(@alignCast(db));

    db_.deinit();
    std.heap.c_allocator.destroy(db_);

    return 0;
}
