const std = @import("std");
const kdbx = @import("kdbx");
const clap = @import("clap");

const VERSION = "0.1.0";

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

var stdout_buffer: [1024]u8 = undefined;
var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
const stdout = &stdout_writer.interface;

var stderr_buffer: [1024]u8 = undefined;
var stderr_writer = std.fs.File.stdout().writer(&stderr_buffer);
const stderr = &stderr_writer.interface;

var stdin_buffer: [1024]u8 = undefined;
var stdin_reader = std.fs.File.stdin().reader(&stdin_buffer);
const stdin = &stdin_reader.interface;

pub fn main() !void {
    var password: ?[]u8 = null;
    defer if (password) |pw| {
        std.crypto.secureZero(u8, pw);
        allocator.free(pw);
    };

    const params = comptime clap.parseParamsComptime(
        \\-h, --help               Display this help and exit.
        \\-l, --list               List all credentials.
        \\--path <str>             Path to a KDBX4 database file.
        \\--password <str>         A password. This should be entered using command line substituation!
        \\-c, --create             Create a new database.
        \\--name <str>             Specify a name.
        \\--cipher <str>           The cipher that should be used for encryption.
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
        .allocator = gpa.allocator(),
    }) catch |err| {
        // Report useful error and exit
        diag.report(stderr, err) catch {};
        return;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        try std.fmt.format(stdout, help_text, .{VERSION});
        return;
    }
    if (res.args.password) |p| {
        password = try allocator.dupe(u8, p);
    }

    // ------------------------------------------------

    if (res.args.create != 0) {
        const path = if (res.args.path) |path| path else {
            std.log.err("create: missing '--path <path>' argument", .{});
            return;
        };

        var db = if (create(&res)) |db| db else return;
        defer db.deinit();

        save(path, &db, res);
    }

    //var database = try kdbx.Database.new(.{
    //    .allocator = allocator,
    //});
    //defer database.deinit();

    //var group1 = try kdbx.Group.new("Demo group", allocator);
    //errdefer group1.deinit();

    //var entry1 = kdbx.Entry.new(allocator);
    //try entry1.set("Title", "Demo Entry", false);
    //try entry1.set("UserName", "max", false);
    //try entry1.set("Password", "supersecret", true);
    //errdefer entry1.deinit();
    //try group1.addEntry(entry1);

    //var entry2 = kdbx.Entry.new(allocator);
    //try entry2.set("Title", "Demo Entry 2", false);
    //try entry2.set("UserName", "peter", false);
    //try entry2.set("Password", "1234@#", true);
    //errdefer entry2.deinit();
    //try group1.addEntry(entry2);

    //try database.body.root.addGroup(group1);

    //var entry3 = kdbx.Entry.new(allocator);
    //try entry3.set("Title", "Demo Entry 3", false);
    //try entry3.set("UserName", "fiona", false);
    //try entry3.set("Password", "foobar", true);
    //errdefer entry3.deinit();
    //try database.body.root.addEntry(entry3);

    //const db_key = kdbx.DatabaseKey{
    //    .password = try allocator.dupe(u8, "1234"),
    //    .allocator = allocator,
    //};
    //defer db_key.deinit();

    //var raw = std.ArrayList(u8).init(allocator);
    //defer raw.deinit();

    //try database.save(
    //    raw.writer(),
    //    db_key,
    //    allocator,
    //);

    //var file = try std.fs.cwd().createFile("db.kdbx", .{});
    //defer file.close();

    //try file.writeAll(raw.items);

    //// --------------------------------------------

    //var fbs = std.io.fixedBufferStream(raw.items);
    //const reader = fbs.reader();

    ////std.debug.print("{s}", .{std.fmt.fmtSliceHexLower(raw.items)});

    //var database2 = kdbx.Database.open(reader, .{
    //    .allocator = allocator,
    //    .key = db_key,
    //}) catch |e| {
    //    std.log.err("unable to decrypt database {any}", .{e});
    //    return;
    //};
    //defer database2.deinit();

    //var root_iterator = database2.body.root.iterate(.entry);
    //while (root_iterator.next()) |node| {
    //    switch (node) {
    //        .entry => |e| std.debug.print("{s}\n", .{e.strings.items[0].value}),
    //        .group => {},
    //    }
    //}
}

fn save(path: []const u8, database: *kdbx.Database, res: anytype) void {
    const pw = if (res.args.password) |pw| pw else {
        std.log.err("save: missing '--password <password>' argument", .{});
        return;
    };

    const db_key = kdbx.DatabaseKey{
        .password = allocator.dupe(u8, pw) catch |e| {
            std.log.err("unable to copy memory ({any})", .{e});
            return;
        },
        .allocator = allocator,
    };
    defer db_key.deinit();

    var raw = std.ArrayList(u8).init(allocator);
    defer raw.deinit();

    database.save(
        raw.writer(),
        db_key,
        allocator,
    ) catch |e| {
        std.log.err("unable to save database ({any})", .{e});
        return;
    };

    var file = std.fs.createFileAbsolute(path, .{}) catch |e| {
        std.log.err("unable to open file '{s}' ({any})", .{ path, e });
        return;
    };
    defer file.close();

    file.writeAll(raw.items) catch |e| {
        std.log.err("unable to write file '{s}' ({any})", .{ path, e });
        return;
    };
}

fn create(res: anytype) ?kdbx.Database {
    const cipher = if (res.args.cipher) |cipher| blk: {
        if (std.mem.eql(u8, cipher, "aes256cbc")) {
            break :blk kdbx.v4.Field.Cipher.aes256_cbc;
        } else {
            std.log.err("create: invalid cipher {s}", .{cipher});
            return null;
        }
    } else {
        std.log.err("create: missing '--cipher <cipher>' argument", .{});
        return null;
    };
    const name = if (res.args.name) |name| name else "Database";

    return kdbx.Database.new(.{
        .generator = "kdbx-cli",
        .name = name,
        .encryption_algorithm = cipher,
        .allocator = allocator,
    }) catch null;
}

const help_text =
    \\kdbx-cli {s}
    \\Copyright (C) 2025 David P. Sugar (r4gus)
    \\License MIT <https://opensource.org/license/MIT>
    \\This is free software: you are free to change and redistribute it.
    \\There is NO WARRANTY, to the extent permitted by law.
    \\
    \\Supported cipher:
    \\ aes256cbc
    \\
    \\Supported KDFs:
    \\ argon2id
    \\
    \\Syntax: kdbx [options]
    \\ Display and modify the content of a KDBX4 credential database.
    \\
    \\Commands:
    \\ -h, --help                                  Display this help and exit.
    \\ -n, --new                                   Create a new entry.
    \\
    \\Options controlling the input:
    \\ --path <str>                                Database file path.
    \\ --password <str>                            A password. This should be entered using command line substituation!
    \\ -c, --create                                Create a new database.
    \\ --name <str>                                Specify a name.
    \\ --cipher <cipher>                           The cipher that should be used for encryption.
    \\
    \\Security considerations:
    \\  The password file should only be readable by the user. Please do not 
    \\  enter your password on the command line as other users might be able 
    \\  to read it.
    \\
    \\Examples:
    \\  kdbx-cli --create -p /home/sugar/Dev/kdbx/passwords.kdbx --password 1234 --name "Test Database" --cipher aes256cbc
    \\
;
