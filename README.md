# KDBX - Keepass Database XML

This Zig module allows you to integrate KDBX support into your application. This format is
used by password databases like [KeePass](https://keepass.info/download.html) and 
[KeePassXC](https://keepassxc.org/) to store passwords, [passkeys](https://fidoalliance.org/passkeys/) 
and other credentials.

> Currently only KDBX4 is supported.

## Getting Started

First add this project as a dependency to your `build.zig.zon` file:

```bash
# Replace <VERSION TAG> with the version you want to use ...
zig fetch --save https://github.com/Zig-Sec/kdbx/archive/refs/tags/<VERSION TAG>.tar.gz

# ... or use the master branch
zig fetch --save git+https://github.com/Zig-Sec/kdbx
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

### Reading a database
```zig
const std = @import("std");
const kdbx = @import("kdbx");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

pub fn main() !void {
    var f = try std.fs.cwd().openFile("test.kdbx", .{});
    defer f.close();
    var reader  = f.reader(&.{});

    const db_key = kdbx.DatabaseKey{
        .password = try allocator.dupe(u8, "1234"),
        .allocator = allocator,
    };
    defer db_key.deinit();

    var database = try Database.open(&reader, .{
        .allocator = allocator,
        .key = db_key,
    });
    defer database.deinit();
    
    // The root group can be accessed via `database.body.root`.
    
    // Iterate over all entries of the root group:
    for (database.body.root.entries.items) |entry| {
        _ = entry;
        //... do something with the entry
    }
    
    // Iterate over all groups of the root group:
    for (database.body.root.groups.items) |group| {
        _ = group;
        //... do something with the group. Each group
        // can contain more entries and groups.
    }
}
```

### Writing a database

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
    // First we create a new database.
    var database = try kdbx.Database.new(.{
        .allocator = allocator,
    });
    defer database.deinit();
    
    // Now lets create an entry.
    var entry1 = kdbx.Entry.new(allocator);
    errdefer entry1.deinit();
    try entry1.set("Title", "Demo Entry", false);
    try entry1.set("UserName", "max", false);
    try entry1.set("Password", "supersecret", true);
    
    // Then we add the entry to our newly created database.
    try database.body.root.addEntry(entry1);
    
    // To save the database, we need to select a database key/ password.
    // We can use the same key to later decrypt the database.
    const db_key = kdbx.DatabaseKey{
        .password = try allocator.dupe(u8, "1234"),
        .allocator = allocator,
    };
    defer db_key.deinit();
    
    // A database can be saved by calling the `save` function on
    // a database object. The function expects a writer as the first
    // argument. This makes it easy to write the database to different
    // container types (e.g. a ArrayList as seen below) or a file.
    var saved_db = std.Io.Writer.Allocating.init(allocator);
    defer saved_db.deinit();

    try database.save(&saved_db.writer, db_key, allocator);
}
```
