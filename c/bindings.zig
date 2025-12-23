const std = @import("std");
const kdbx = @import("kdbx");

const ENOENT: c_int = 2; // No such file or directory
const EIO: c_int = 5; // Input/output error
const ENOMEM: c_int = 12; // Cannot allocate memory
const EACCES: c_int = 13; // Permission denied

fn kdbx_open_with_password_(
    reader: *std.Io.Reader,
    pw: []u8,
    code: *c_int,
) !*kdbx.Database {
    const key = kdbx.DatabaseKey{
        .password = pw,
    };

    var database = kdbx.Database.open(reader, .{
        .allocator = std.heap.c_allocator,
        .key = key,
    }) catch {
        code.* = EACCES;
        return error.EACCES;
    };
    errdefer database.deinit();

    const db_ = std.heap.c_allocator.create(kdbx.Database) catch {
        code.* = ENOMEM;
        return error.ENOMEM;
    };
    db_.* = database;

    return db_;
}

/// Open a KDBX database using a password.
///
/// On success, the function will populate db with a database instance and return 0.
/// On error, a non-zero error value is returned.
pub export fn kdbx_open_with_password(
    db: **anyopaque,
    path: [*c]u8,
    path_len: usize,
    password: [*c]u8,
    password_len: usize,
) c_int {
    const path_ = path[0..path_len];
    const password_ = password[0..password_len];
    var ret: c_int = 0;

    var f = std.fs.cwd().openFile(
        path_,
        .{},
    ) catch {
        return ENOENT;
    };
    defer f.close();

    var buffer: [1024]u8 = undefined;
    var reader = f.reader(&buffer);

    const db_ = kdbx_open_with_password_(&reader.interface, password_, &ret) catch {
        return ret;
    };

    db.* = @as(*anyopaque, @ptrCast(db_));
    return ret;
}

/// Close a KDBX database.
///
/// The passed database db must be valid.
///
/// The function will always return success (0).
pub export fn kdbx_close(
    db: *anyopaque,
) c_int {
    var db_: *kdbx.Database = @ptrCast(@alignCast(db));

    db_.deinit();
    std.heap.c_allocator.destroy(db_);

    return 0;
}

/// Get the group specified by `path`.
///
/// On succuess, the function will assign the group specified by `path` to `group`.
/// On error, a non-zero error value is returned.
pub export fn kdbx_db_get_group(
    group: **anyopaque,
    db: *anyopaque,
    path: [*c]u8,
    path_len: usize,
) c_int {
    var db_: *kdbx.Database = @ptrCast(@alignCast(db));
    const path_ = path[0..path_len];

    const g = db_.getGroup(path_);
    if (g == null) return ENOENT;

    group.* = @ptrCast(g.?);
    return 0;
}

/// Get the entry of the `group` that matches the `value` for the given `key`.
///
/// On success, the matching entry is assigned to `entry`.
/// On error, a non-zero error value is returned.
pub export fn kdbx_group_get_entry_by_key(
    entry: **anyopaque,
    group: *anyopaque,
    key: [*c]u8,
    key_len: usize,
    value: [*c]u8,
    value_len: usize,
) c_int {
    var group_: *kdbx.Group = @ptrCast(@alignCast(group));

    const e = group_.getEntryByValue(key[0..key_len], value[0..value_len]);
    if (e == null) return ENOENT;

    entry.* = @ptrCast(e.?);
    return 0;
}

/// Get the value for the specified `key`.
///
/// On success, the function will return the value as null-terminated string.
/// Depending on the type of data returned, it might be base64 encoded.
/// The caller is responsible for freeing the string.
///
/// On error, the function will return null.
pub export fn kdbx_entry_get_value(
    entry: *anyopaque,
    key: [*c]u8,
    key_len: usize,
) [*c]u8 {
    var entry_: *kdbx.Entry = @ptrCast(@alignCast(entry));

    const v = entry_.get(key[0..key_len]);
    if (v == null) return null;

    const cv = std.heap.c_allocator.dupeZ(u8, v.?) catch {
        return null;
    };

    return cv.ptr;
}
