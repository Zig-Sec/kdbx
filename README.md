# KDBX - Keepass Database XML

This Zig module allows you to integrate KDBX support into your application.

> Currently only KDBX4 is supported.

## Getting Started

First add this project as a dependency to your `build.zig.zon` file:

```zig
.{
    // ...

    .dependencies = .{
        // ...

        .kdbx = .{
            .url = "https://github.com/r4gus/kdbx/archive/master.tar.gz",
            .hash = <hash>,
        }
    },

    // ...
}
```

Then, within your `build.zig` add the following code:

```zig
const kdbx_dep = b.dependency("kdbx", .{
    .target = target,
    .optimize = optimize,
});
const kdbx_module = zbor_dep.module("kdbx");

// ...

exe.root_module.addImport("kdbx", kdbx_module);
```

Then within your project just use `@import("kdbx")`.

## Reading and writing databases

> When saving, the inner XML data structure is generated from
> the Zig objects that represent the database, i.e., unsupported
> fields are lost when reading and then writing a existing database.
>
> If in doubt, backup your database!
>
> Feel free to open pull requests for missing features.

```zig
const std = @import("std");
const kdbx = @import("kdbx");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

pub fn main() !void {
    var database = try kdbx.Database.new(.{
        .allocator = allocator,
    });
    defer database.deinit();

    var entry1 = kdbx.Entry.new(allocator);
    try entry1.set("Title", "Demo Entry", false);
    try entry1.set("UserName", "max", false);
    try entry1.set("Password", "supersecret", true);
    errdefer entry1.deinit();

    try database.body.root.addEntry(entry1);

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
```

> Also see `main.zig` for an example.
