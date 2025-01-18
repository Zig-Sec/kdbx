const std = @import("std");
const root = @import("../root.zig");
const v4 = root.v4;
const Field = v4.Field;
const Header = v4.Header;
const HVersion = v4.HVersion;
const Keys = v4.Keys;
const XML = v4.XML;
const Meta = v4.Meta;
const KeyValue = v4.KeyValue;
const Group = v4.Group;
const Entry = v4.Entry;
const Times = v4.Times;
const AutoType = v4.AutoType;
const Icon = v4.Icon;
const InnerHeader = v4.InnerHeader;
const Body = v4.Body;
const Database = root.Database;

const Uuid = @import("uuid");

const DatabaseKey = @import("../DatabaseKey.zig");

const ChaCha20 = @import("../chacha.zig").ChaCha20;

test "HVersion #1" {
    var v = HVersion.new(0x9AA2D903, 0xB54BFB67, 1, 4);

    try std.testing.expectEqualSlices(u8, "\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x01\x00\x04\x00", &v.raw);
    try std.testing.expectEqual(@as(u32, 0x9AA2D903), v.getSignature1());
    try std.testing.expectEqual(@as(u32, 0xB54BFB67), v.getSignature2());
    try std.testing.expectEqual(@as(u16, 1), v.getMinorVersion());
    try std.testing.expectEqual(@as(u16, 4), v.getMajorVersion());

    v.setSignature2(0xcafebabe);
    v.setMinorVersion(3);
    v.setMajorVersion(5);
    try std.testing.expectEqual(@as(u32, 0xcafebabe), v.getSignature2());
    try std.testing.expectEqual(@as(u16, 3), v.getMinorVersion());
    try std.testing.expectEqual(@as(u16, 5), v.getMajorVersion());
}

test "decode outer header" {
    const s = "\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x01\x00\x04\x00\x02\x10\x00\x00\x00\x31\xc1\xf2\xe6\xbf\x71\x43\x50\xbe\x58\x05\x21\x6a\xfc\x5a\xff\x03\x04\x00\x00\x00\x01\x00\x00\x00\x04\x20\x00\x00\x00\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x07\x10\x00\x00\x00\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x0b\x8b\x00\x00\x00\x00\x01\x42\x05\x00\x00\x00\x24\x55\x55\x49\x44\x10\x00\x00\x00\xef\x63\x6d\xdf\x8c\x29\x44\x4b\x91\xf7\xa9\xa4\x03\xe3\x0a\x0c\x05\x01\x00\x00\x00\x49\x08\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x05\x01\x00\x00\x00\x4d\x08\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x04\x01\x00\x00\x00\x50\x04\x00\x00\x00\x08\x00\x00\x00\x42\x01\x00\x00\x00\x53\x20\x00\x00\x00\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x04\x01\x00\x00\x00\x56\x04\x00\x00\x00\x13\x00\x00\x00\x00\x00\x04\x00\x00\x00\x0d\x0a\x0d\x0a\xed\x5b\xd6\x7f\x65\x86\xe4\x59\xf1\xa0\x5d\xbe\xae\x4a\xaa\x72\x9a\x6b\x85\x51\x83\x87\x2a\xc4\x65\xaf\x2d\x5c\x5b\x77\x1d\x6d";

    var fbs = std.io.fixedBufferStream(s);

    const header = try Header.readAlloc(fbs.reader(), std.testing.allocator);
    defer header.deinit();

    const cid = header.getCipherId();
    try std.testing.expectEqual(Field.Cipher.aes256_cbc, cid);

    const comp = header.getCompression();
    try std.testing.expectEqual(Field.Compression.gzip, comp);

    const seed = header.getMainSeed();
    try std.testing.expectEqualSlices(u8, "\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78", &seed);

    const iv = header.getEncryptionIv();
    try std.testing.expectEqualSlices(u8, "\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78", &iv);

    const kdf = header.getKdfParameters();
    try std.testing.expectEqualSlices(u8, "\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78", &kdf.argon2.s);
    try std.testing.expectEqual(@as(u64, 2), kdf.argon2.i);
    try std.testing.expectEqual(@as(u64, 0x40000000), kdf.argon2.m);
    try std.testing.expectEqual(@as(u32, 8), kdf.argon2.p);
    try std.testing.expectEqual(@as(u32, 0x13), kdf.argon2.v);
}

test "decode and encode header #1" {
    const s = "\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x01\x00\x04\x00\x02\x10\x00\x00\x00\x31\xc1\xf2\xe6\xbf\x71\x43\x50\xbe\x58\x05\x21\x6a\xfc\x5a\xff\x03\x04\x00\x00\x00\x01\x00\x00\x00\x04\x20\x00\x00\x00\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x07\x10\x00\x00\x00\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x0b\x8b\x00\x00\x00\x00\x01\x42\x05\x00\x00\x00\x24\x55\x55\x49\x44\x10\x00\x00\x00\xef\x63\x6d\xdf\x8c\x29\x44\x4b\x91\xf7\xa9\xa4\x03\xe3\x0a\x0c\x05\x01\x00\x00\x00\x49\x08\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x05\x01\x00\x00\x00\x4d\x08\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x04\x01\x00\x00\x00\x50\x04\x00\x00\x00\x08\x00\x00\x00\x42\x01\x00\x00\x00\x53\x20\x00\x00\x00\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x04\x01\x00\x00\x00\x56\x04\x00\x00\x00\x13\x00\x00\x00\x00\x00\x04\x00\x00\x00\x0d\x0a\x0d\x0a\xed\x5b\xd6\x7f\x65\x86\xe4\x59\xf1\xa0\x5d\xbe\xae\x4a\xaa\x72\x9a\x6b\x85\x51\x83\x87\x2a\xc4\x65\xaf\x2d\x5c\x5b\x77\x1d\x6d";
    const s2 = "\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x01\x00\x04\x00\x02\x10\x00\x00\x00\x31\xc1\xf2\xe6\xbf\x71\x43\x50\xbe\x58\x05\x21\x6a\xfc\x5a\xff\x03\x04\x00\x00\x00\x01\x00\x00\x00\x04\x20\x00\x00\x00\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x07\x10\x00\x00\x00\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x0b\x8b\x00\x00\x00\x00\x01\x42\x05\x00\x00\x00\x24\x55\x55\x49\x44\x10\x00\x00\x00\xef\x63\x6d\xdf\x8c\x29\x44\x4b\x91\xf7\xa9\xa4\x03\xe3\x0a\x0c\x05\x01\x00\x00\x00\x49\x08\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x05\x01\x00\x00\x00\x4d\x08\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x04\x01\x00\x00\x00\x50\x04\x00\x00\x00\x08\x00\x00\x00\x42\x01\x00\x00\x00\x53\x20\x00\x00\x00\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x12\x34\x56\x78\x04\x01\x00\x00\x00\x56\x04\x00\x00\x00\x13\x00\x00\x00\x00\x00\x04\x00\x00\x00\x0d\x0a\x0d\x0a";

    var fbs = std.io.fixedBufferStream(s);

    var header = try Header.readAlloc(fbs.reader(), std.testing.allocator);
    defer header.deinit();

    try header.updateRawHeader();

    try std.testing.expectEqualSlices(u8, s2, header.raw_header);
}

const db = @embedFile("../static/testdb.kdbx");
const db2 = @embedFile("../static/TestDb2.kdbx");

test "verify kdbx4 header mac (positive test)" {
    var fbs = std.io.fixedBufferStream(db);

    const header = try Header.readAlloc(fbs.reader(), std.testing.allocator);
    defer header.deinit();

    var db_key = DatabaseKey{
        .password = try std.testing.allocator.dupe(u8, "supersecret"),
        .allocator = std.testing.allocator,
    };
    defer db_key.deinit();
    var keys = try header.deriveKeys(db_key);
    defer keys.deinit();

    try header.checkMac(&keys);
}

test "recalculate raw header, hash, and mac #1" {
    var fbs = std.io.fixedBufferStream(db);

    var header = try Header.readAlloc(fbs.reader(), std.testing.allocator);
    defer header.deinit();

    const hash = header.hash;
    const mac = header.mac;

    var db_key = DatabaseKey{
        .password = try std.testing.allocator.dupe(u8, "supersecret"),
        .allocator = std.testing.allocator,
    };
    defer db_key.deinit();
    var keys = try header.deriveKeys(db_key);
    defer keys.deinit();

    header.hash = .{0} ** 32;
    header.mac = .{0} ** 32;

    try header.updateRawHeader();
    header.updateHash();
    header.updateMac(&keys);

    try std.testing.expectEqualSlices(u8, &hash, &header.hash);
    try std.testing.expectEqualSlices(u8, &mac, &header.mac);
}

test "verify kdbx4 header mac (negative test)" {
    var fbs = std.io.fixedBufferStream(db);

    const header = try Header.readAlloc(fbs.reader(), std.testing.allocator);
    defer header.deinit();

    var db_key = DatabaseKey{
        .password = try std.testing.allocator.dupe(u8, "Supersecret"),
        .allocator = std.testing.allocator,
    };
    defer db_key.deinit();
    var keys = try header.deriveKeys(db_key);
    defer keys.deinit();

    try std.testing.expectError(error.Authenticity, header.checkMac(&keys));
}

test "the decryption of a kdbx4 file #1" {
    var fbs = std.io.fixedBufferStream(db);
    const reader = fbs.reader();

    const header = try Header.readAlloc(reader, std.testing.allocator);
    defer header.deinit();

    var db_key = DatabaseKey{
        .password = try std.testing.allocator.dupe(u8, "supersecret"),
        .allocator = std.testing.allocator,
    };
    defer db_key.deinit();
    var keys = try header.deriveKeys(db_key);
    defer keys.deinit();
    try header.checkMac(&keys);

    var body = try Body.readAlloc(reader, &header, &keys, std.testing.allocator);
    defer body.deinit();

    try std.testing.expectEqual(InnerHeader.StreamCipher.ChaCha20, body.inner_header.stream_cipher);

    //std.debug.print("{s}", .{std.fmt.fmtSliceHexLower(body.inner_header.stream_key)});
    //std.debug.print("{s}\n", .{body.xml});

    const body_xml = try body.getXml(std.testing.allocator);
    defer body_xml.deinit();

    // Meta
    try std.testing.expectEqualSlices(u8, "KeePassXC", body_xml.meta.generator);
    try std.testing.expectEqualSlices(u8, "Test Database", body_xml.meta.database_name);
    try std.testing.expectEqual(@as(i64, 63860739034), body_xml.meta.database_name_changed);
    try std.testing.expectEqualSlices(u8, "This is a test database", body_xml.meta.database_description.?);
    try std.testing.expectEqual(@as(i64, 365), body_xml.meta.maintenance_history_days);
    try std.testing.expectEqual(@as(i64, -1), body_xml.meta.master_key_change_rec);
    try std.testing.expectEqual(@as(i64, -1), body_xml.meta.master_key_change_force);
    try std.testing.expectEqual(false, body_xml.meta.memory_protection.protect_title);
    try std.testing.expectEqual(false, body_xml.meta.memory_protection.protect_user_name);
    try std.testing.expectEqual(true, body_xml.meta.memory_protection.protect_password);
    try std.testing.expectEqual(false, body_xml.meta.memory_protection.protect_url);
    try std.testing.expectEqual(false, body_xml.meta.memory_protection.protect_notes);
    try std.testing.expectEqual(true, body_xml.meta.recycle_bin_enabled);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.meta.recycle_bin_uuid);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.meta.entry_template_group);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.meta.last_selected_group);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.meta.last_top_visible_group);
    try std.testing.expectEqual(@as(i64, 10), body_xml.meta.history_max_items);
    try std.testing.expectEqual(@as(i64, 6291456), body_xml.meta.history_max_size);

    try std.testing.expectEqualSlices(u8, "KPXC_DECRYPTION_TIME_PREFERENCE", body_xml.meta.custom_data.items[0].key);
    try std.testing.expectEqualSlices(u8, "100", body_xml.meta.custom_data.items[0].value);

    try std.testing.expectEqualSlices(u8, "KPXC_RANDOM_SLUG", body_xml.meta.custom_data.items[1].key);
    try std.testing.expectEqualSlices(u8, "998be628c7527f3496dd5ec88960ea9f0542cb3196d83200f257d38f24ed234e93550d2db8f784084dc387601ad233416875951170c4cedf969be95ef0654b69e8893133e1a2982c76c16aabca5dd756b1d3549f5efe96f236611239e28c75e5277a7791a1aa557a9413201a76266fdd6edfba5ec4ad5c80af", body_xml.meta.custom_data.items[1].value);

    try std.testing.expectEqualSlices(u8, "_LAST_MODIFIED", body_xml.meta.custom_data.items[2].key);
    try std.testing.expectEqualSlices(u8, "Sat Aug 31 22:13:03 2024 GMT", body_xml.meta.custom_data.items[2].value);

    // Root Group
    try std.testing.expectEqualSlices(u8, "4c366769-07e8-4bc9-8091-3e5caefe9710", &Uuid.urn.serialize(body_xml.root.uuid));
    try std.testing.expectEqualSlices(u8, "Root", body_xml.root.name);
    try std.testing.expectEqual(@as(i64, 48), body_xml.root.icon_id);
    try std.testing.expectEqual(true, body_xml.root.is_expanded);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.root.last_top_visible_entry);

    // Entry 0
    try std.testing.expectEqualSlices(u8, "0ff2cbb1-69d5-4fda-bb68-da67291dcb07", &Uuid.urn.serialize(body_xml.root.entries.items[0].uuid));
    try std.testing.expectEqual(@as(i64, 0), body_xml.root.entries.items[0].icon_id);
    try std.testing.expectEqualSlices(u8, "programming", body_xml.root.entries.items[0].tags.?);
    try std.testing.expectEqualSlices(u8, "", body_xml.root.entries.items[0].get("Notes").?);
    try std.testing.expectEqualSlices(u8, "123456", body_xml.root.entries.items[0].get("Password").?);
    try std.testing.expectEqualSlices(u8, "https://github.com", body_xml.root.entries.items[0].get("URL").?);
    try std.testing.expectEqualSlices(u8, "Github", body_xml.root.entries.items[0].get("Title").?);
    try std.testing.expectEqualSlices(u8, "max", body_xml.root.entries.items[0].get("UserName").?);

    // Entry 1
    try std.testing.expectEqualSlices(u8, "164b7b20-7220-4471-aebf-3023a704b2f4", &Uuid.urn.serialize(body_xml.root.entries.items[1].uuid));
    try std.testing.expectEqual(@as(i64, 0), body_xml.root.entries.items[1].icon_id);
    try std.testing.expectEqualSlices(u8, "", body_xml.root.entries.items[1].tags.?);
    try std.testing.expectEqualSlices(u8, "", body_xml.root.entries.items[1].get("Notes").?);
    try std.testing.expectEqualSlices(u8, "654321", body_xml.root.entries.items[1].get("Password").?);
    try std.testing.expectEqualSlices(u8, "https://codeberg.org", body_xml.root.entries.items[1].get("URL").?);
    try std.testing.expectEqualSlices(u8, "Codeberg", body_xml.root.entries.items[1].get("Title").?);
    try std.testing.expectEqualSlices(u8, "max", body_xml.root.entries.items[1].get("UserName").?);
}

test "the decryption of a kdbx4 file #2" {
    var fbs = std.io.fixedBufferStream(db2);
    const reader = fbs.reader();

    const header = try Header.readAlloc(reader, std.testing.allocator);
    defer header.deinit();

    var db_key = DatabaseKey{
        .password = try std.testing.allocator.dupe(u8, "foobar"),
        .allocator = std.testing.allocator,
    };
    defer db_key.deinit();
    var keys = try header.deriveKeys(db_key);
    defer keys.deinit();
    try header.checkMac(&keys);

    var body = try Body.readAlloc(reader, &header, &keys, std.testing.allocator);
    defer body.deinit();

    try std.testing.expectEqual(InnerHeader.StreamCipher.ChaCha20, body.inner_header.stream_cipher);

    //std.debug.print("{s}\n", .{body.xml});

    const body_xml = try body.getXml(std.testing.allocator);
    defer body_xml.deinit();

    // Meta
    try std.testing.expectEqualSlices(u8, "KeePassXC", body_xml.meta.generator);
    try std.testing.expectEqualSlices(u8, "Zig Database Impl", body_xml.meta.database_name);
    try std.testing.expectEqualSlices(u8, "This is another test database for the KDBX4 Zig impl", body_xml.meta.database_description.?);
    try std.testing.expectEqual(@as(i64, 365), body_xml.meta.maintenance_history_days);
    try std.testing.expectEqual(@as(i64, -1), body_xml.meta.master_key_change_rec);
    try std.testing.expectEqual(@as(i64, -1), body_xml.meta.master_key_change_force);
    try std.testing.expectEqual(false, body_xml.meta.memory_protection.protect_title);
    try std.testing.expectEqual(false, body_xml.meta.memory_protection.protect_user_name);
    try std.testing.expectEqual(true, body_xml.meta.memory_protection.protect_password);
    try std.testing.expectEqual(false, body_xml.meta.memory_protection.protect_url);
    try std.testing.expectEqual(false, body_xml.meta.memory_protection.protect_notes);
    try std.testing.expectEqual(true, body_xml.meta.recycle_bin_enabled);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.meta.recycle_bin_uuid);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.meta.entry_template_group);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.meta.last_selected_group);
    try std.testing.expectEqual(@as(Uuid.Uuid, 0), body_xml.meta.last_top_visible_group);
    try std.testing.expectEqual(@as(i64, 10), body_xml.meta.history_max_items);
    try std.testing.expectEqual(@as(i64, 6291456), body_xml.meta.history_max_size);

    // Custom icon
    try std.testing.expectEqual(@as(usize, 1), body_xml.meta.custom_icons.?.items.len);
    try std.testing.expectEqualSlices(u8, "ba5c5602-21dc-464e-ab87-014d487a74c1", &Uuid.urn.serialize(body_xml.meta.custom_icons.?.items[0].uuid));
    try std.testing.expectEqualSlices(u8, "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEnRFWHRfcV9pY29PcmlnRGVwdGgAMzLV4rjsAAAEl0lEQVRYha1XUWhbVRj+vnPTNNvaSNnuTZpkJY4ryJ1uD3UrIjL3Ioo6fRLZ08CHKjIRHfowWJbpFHzQiUN9EB8F6YNlKMM5GRsozjnRDqpgkNgmze1Nts60KW2a5PdhyXaX3LTZmu8p5//P/3/fOffk/88hOoRlWf65QmGvAPsgYgGICBkBAIrMAJgBOUng1MCWLecmJyfLneTlWhPiuh5eIhMish9AsEO9RZJfBkSS6XzevisBpmn2LhSLhwG8LiKbOiS+PTlZAvBBXzB4PJVKLXcsoL7qcREZuRtiDyEXAyLPee1Gi4CYYeyoiHwrQKwb5C6ijI98KuM4E20FxHU9vARc6ja5W0QA2OXeCdX4YZpm7xI57iYn8CeBr0hevQu+6wTGCPzWMAgQWyLHTdPsbRGwUCwebv7mJE/Y+fwL91tWGEq9CNKuOxZAXiFwgcB5kBMA/qvHXCNwcLOuh+x8/nmSx905RWSkfrgbi7x56FLNp52attu27UuNsaXrfdc0bWh0dPSvZDJZa0rMWCx2n6Zp+ampqbmGPRQK3Yta7Z+mhZUCImY6n7cJAGHD+FREXmreQ+XzPZTL5S577W+nGBwcHKpVKv8220l+ZjvOy8qyLH+9yLSiWrXWQw4AIrK9jX2/ZVl+NVco7IVHhSNZgqZdWK8ATdN+IVnwcAXnCoW9SoB9bWKP5XK5lq27U2Sz2asQedPLJ8A+VW8sLfD5/V+vl7yBwKZN3rlELAUg0mwnWZqenk51S0A6nb5OcsrDFVGNltoEh6R0SwAAQGS2xURGFF3F6NZc2dJVcgAgW3ISUAqA1wntD4VCRre44/F4AB6fGkBeAfC8MCiRx7slYHlxcY+I9Hq4bEWRn72CRORVEVnzxtQJBHjNy06Riwrk+TZBuwZDoTfWSx7W9QMi8oSnkzyvggMD3wOY9xQh8n7YMI4NDw/33ClxIpFQYcM4JMDnbabMD4icaTSjkyLySl3Vhxr5a1XkLYjsAAAC0yC/UMCPyu+/nMlkrnll3LZt2z2lUmlYAQ/XRA5AxGwnkEqdtGdnDyoA8ImcIFkGAN4IzG8WeQTk7wAgwFYRSVRFzqyUy6cSiUTLXxcAFufnx1Gr/VCr1d5ZlZxc7hE5UV/cDYQNIykiR+rDos/v305yQ6Vc/sldFzSlnp2ZnT3llTgcDj8m1eq5dsQuAUnbcY4CriLUFwy+W7/ZAECwWi4nM5nM3wGRB0keAvCRIkc39vd/1y6xz+ebaOdzsU/0BYPv3Ry6fZFIZGt1ZeUigEEAVWraM7Ztn14zqQshXV8B4Gvjzmk9PSMzMzPTngIAIGoYOysip2+KIM8COEtgXoDQo3v2HB8bG6uuIqACQPMi95FPZh3nD7fRs9BEo9FYZWXlG4jsbPZt1vXe1d59IV2vorm/kFeUpj2dy+VaOqLnac5ms5n+YHCEZJLkbU+qxcVFzxg33S1elkm+vWHjxt1e5G0FAEAqlVq2HedoD7CdSn0MoAhyIR6PV1ZlJ+dALpD8xOf3P2A7zpF0Or20hui1Yel639DQ0MBa86LRaMw0zU5f0fgfUk/VbnmdnBIAAAAASUVORK5CYII=", body_xml.meta.custom_icons.?.items[0].data);

    // Entry 0
    try std.testing.expectEqualSlices(u8, "5dd56835-af4c-49a3-aa67-f458f18397ef", &Uuid.urn.serialize(body_xml.root.entries.items[0].uuid));
    try std.testing.expectEqualSlices(u8, "ba5c5602-21dc-464e-ab87-014d487a74c1", &Uuid.urn.serialize(body_xml.root.entries.items[0].custom_icon_uuid.?));
    try std.testing.expectEqual(@as(i64, 0), body_xml.root.entries.items[0].icon_id);
    try std.testing.expectEqualSlices(u8, "dev,programming", body_xml.root.entries.items[0].tags.?);
    try std.testing.expectEqualSlices(u8, "Recovery keys:\n\n123-456-789\n123-456-789", body_xml.root.entries.items[0].get("Notes").?);
    try std.testing.expectEqualSlices(u8, "4~+aSX=&=~u;7a$XrjML", body_xml.root.entries.items[0].get("Password").?);
    try std.testing.expectEqualSlices(u8, "https://github.com", body_xml.root.entries.items[0].get("URL").?);
    try std.testing.expectEqualSlices(u8, "Github", body_xml.root.entries.items[0].get("Title").?);
    try std.testing.expectEqualSlices(u8, "max123", body_xml.root.entries.items[0].get("UserName").?);

    // Entry 1
    try std.testing.expectEqualSlices(u8, "66a6757f-76e2-47a6-b828-5cb907cc99f7", &Uuid.urn.serialize(body_xml.root.entries.items[1].uuid));
    try std.testing.expect(body_xml.root.entries.items[1].custom_icon_uuid == null);
    try std.testing.expectEqual(@as(i64, 0), body_xml.root.entries.items[1].icon_id);
    try std.testing.expectEqualSlices(u8, "coding,programming", body_xml.root.entries.items[1].tags.?);
    try std.testing.expectEqualSlices(u8, "", body_xml.root.entries.items[1].get("Notes").?);
    try std.testing.expectEqualSlices(u8, "L&%)o[d3~)L8`BJ>1t\\h", body_xml.root.entries.items[1].get("Password").?);
    try std.testing.expectEqualSlices(u8, "https://codeberg.de", body_xml.root.entries.items[1].get("URL").?);
    try std.testing.expectEqualSlices(u8, "Codeberg", body_xml.root.entries.items[1].get("Title").?);
    try std.testing.expectEqualSlices(u8, "max@web.de", body_xml.root.entries.items[1].get("UserName").?);

    // Root / Work
    try std.testing.expectEqualSlices(u8, "Work", body_xml.root.groups.items[0].name);

    // Root / Work . Entry 0
    try std.testing.expectEqualSlices(u8, "ZzIE!7ml-HT3c$i;48ZY", body_xml.root.groups.items[0].entries.items[0].get("Password").?);

    // Root / Work . Entry 1
    try std.testing.expectEqualSlices(u8, "7532", body_xml.root.groups.items[0].entries.items[1].get("Password").?);

    // Root / Work / Project One
    try std.testing.expectEqualSlices(u8, "Project One", body_xml.root.groups.items[0].groups.items[0].name);

    // Root / Work / Project One
    try std.testing.expectEqualSlices(u8, "21c0be125544bd4f1e8c3503294ef4fb40bf212d04a7ab4ecfe2d46442585febd115385eb48d45ca34e7726a5762b0ea2fe2271130dce00f83ad5c8620689b0c1ca2fa9a174dced7a9a68a0b3caec10d", body_xml.root.groups.items[0].groups.items[0].entries.items[0].get("Key").?);

    // Root / Shopping
    try std.testing.expectEqualSlices(u8, "Shopping", body_xml.root.groups.items[1].name);

    // Root / Shopping . Entry 0
    try std.testing.expectEqualSlices(u8, "4[PXs~cVy^*YD;Y}MI5~", body_xml.root.groups.items[1].entries.items[0].get("Password").?);

    // Root / Shopping . Entry 1
    try std.testing.expectEqualSlices(u8, "s]{)iQd#6[pyU8:.hpel", body_xml.root.groups.items[1].entries.items[1].get("Password").?);

    // Root / KeePassXC-Browser Passwords
    try std.testing.expectEqualSlices(u8, "KeePassXC-Browser Passwords", body_xml.root.groups.items[2].name);
    try std.testing.expectEqualSlices(u8, "OfRg2GQ4WiRHNtnrOWhalG-5iw-gXKq_JVaUnWqpeRc", body_xml.root.groups.items[2].entries.items[0].get("KPEX_PASSKEY_CREDENTIAL_ID").?);
    try std.testing.expectEqualSlices(u8, "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfVXUrA29p2LnqC3T\nB/qindmNV+y+6+Cn5AwH/j3Iz0+hRANCAAQRKLuox37xlTHnumSyvTMlHh1VML2e\nSxtYwceA/pq1gSM3XORnXwnscNBaEJG81HJp6+T5MiimPts7VwUj9G0s\n-----END PRIVATE KEY-----\n", body_xml.root.groups.items[2].entries.items[0].get("KPEX_PASSKEY_PRIVATE_KEY_PEM").?);
    try std.testing.expectEqualSlices(u8, "passkey.org", body_xml.root.groups.items[2].entries.items[0].get("KPEX_PASSKEY_RELYING_PARTY").?);
    try std.testing.expectEqualSlices(u8, "peter", body_xml.root.groups.items[2].entries.items[0].get("KPEX_PASSKEY_USERNAME").?);
    try std.testing.expectEqualSlices(u8, "DEMO__9fX19ERU1P", body_xml.root.groups.items[2].entries.items[0].get("KPEX_PASSKEY_USER_HANDLE").?);
}

test "the decryption of a kdbx4 file #3" {
    var fbs = std.io.fixedBufferStream(db);
    const reader = fbs.reader();

    var db_key = DatabaseKey{
        .password = try std.testing.allocator.dupe(u8, "supersecret"),
        .allocator = std.testing.allocator,
    };
    defer db_key.deinit();

    var database = try Database.open(reader, .{
        .key = db_key,
        .allocator = std.testing.allocator,
    });
    defer database.deinit();

    // Meta
    try std.testing.expectEqualSlices(u8, "KeePassXC", database.body.meta.generator);
    try std.testing.expectEqualSlices(u8, "Test Database", database.body.meta.database_name);
    try std.testing.expectEqual(@as(i64, 63860739034), database.body.meta.database_name_changed);
    try std.testing.expectEqualSlices(u8, "This is a test database", database.body.meta.database_description.?);
    try std.testing.expectEqual(@as(i64, 365), database.body.meta.maintenance_history_days);
    try std.testing.expectEqual(@as(i64, -1), database.body.meta.master_key_change_rec);
    try std.testing.expectEqual(@as(i64, -1), database.body.meta.master_key_change_force);
}

test "serialize Times to XML" {
    const t = Times{
        .last_modification_time = 0x0edbb52295,
        .creation_time = 0x0edbb37087,
        .last_access_time = 0x0edbb52295,
        .expiry_time = 0x0edbb37087,
        .expires = false,
        .usage_count = 0,
        .location_changed = 0x0edbb37091,
    };

    var arr = std.ArrayList(u8).init(std.testing.allocator);
    defer arr.deinit();

    try t.toXml(arr.writer(), 0, std.testing.allocator);

    const expected: []const u8 =
        \\<Times>
        \\  <LastModificationTime>lSK12w4AAAA=</LastModificationTime>
        \\  <CreationTime>h3Cz2w4AAAA=</CreationTime>
        \\  <LastAccessTime>lSK12w4AAAA=</LastAccessTime>
        \\  <ExpiryTime>h3Cz2w4AAAA=</ExpiryTime>
        \\  <Expires>False</Expires>
        \\  <UsageCount>0</UsageCount>
        \\  <LocationChanged>kXCz2w4AAAA=</LocationChanged>
        \\</Times>
        \\
    ;

    try std.testing.expectEqualSlices(u8, expected, arr.items);
}

test "serialize AutoType to XML" {
    const t = AutoType{
        .enabled = true,
        .data_transfer_obfuscation = 0,
        .default_sequence = null,
    };

    var arr = std.ArrayList(u8).init(std.testing.allocator);
    defer arr.deinit();

    try t.toXml(arr.writer(), 0, std.testing.allocator);

    const expected: []const u8 =
        \\<AutoType>
        \\  <Enabled>True</Enabled>
        \\  <DataTransferObfuscation>0</DataTransferObfuscation>
        \\  <DefaultSequence/>
        \\</AutoType>
        \\
    ;

    try std.testing.expectEqualSlices(u8, expected, arr.items);
}

test "serialize entry #1" {
    const allocator = std.testing.allocator;

    const expected =
        \\<Entry>
        \\  <UUID>D/LLsWnVT9q7aNpnKR3LBw==</UUID>
        \\  <IconID>0</IconID>
        \\  <ForegroundColor/>
        \\  <BackgroundColor/>
        \\  <OverrideURL/>
        \\  <Tags>programming</Tags>
        \\  <Times>
        \\    <LastModificationTime>Noxl3g4AAAA=</LastModificationTime>
        \\    <CreationTime>HIxl3g4AAAA=</CreationTime>
        \\    <LastAccessTime>Noxl3g4AAAA=</LastAccessTime>
        \\    <ExpiryTime>HIxl3g4AAAA=</ExpiryTime>
        \\    <Expires>False</Expires>
        \\    <UsageCount>0</UsageCount>
        \\    <LocationChanged>Noxl3g4AAAA=</LocationChanged>
        \\  </Times>
        \\  <String>
        \\    <Key>Notes</Key>
        \\    <Value/>
        \\  </String>
        \\  <String>
        \\    <Key>Password</Key>
        \\    <Value Protected="True">h16dtqbi</Value>
        \\  </String>
        \\  <String>
        \\    <Key>Title</Key>
        \\    <Value>Github</Value>
        \\  </String>
        \\  <String>
        \\    <Key>URL</Key>
        \\    <Value>https://github.com</Value>
        \\  </String>
        \\  <String>
        \\    <Key>UserName</Key>
        \\    <Value>max</Value>
        \\  </String>
        \\  <AutoType>
        \\    <Enabled>True</Enabled>
        \\    <DataTransferObfuscation>0</DataTransferObfuscation>
        \\    <DefaultSequence/>
        \\  </AutoType>
        \\  <History/>
        \\</Entry>
        \\
    ;

    var arr = std.ArrayList(KeyValue).init(allocator);

    try arr.append(KeyValue{
        .key = try allocator.dupe(u8, "Notes"),
        .value = try allocator.dupe(u8, ""),
    });
    try arr.append(KeyValue{
        .key = try allocator.dupe(u8, "Password"),
        .value = try allocator.dupe(u8, "123456"),
        .protected = true,
    });
    try arr.append(KeyValue{
        .key = try allocator.dupe(u8, "Title"),
        .value = try allocator.dupe(u8, "Github"),
    });
    try arr.append(KeyValue{
        .key = try allocator.dupe(u8, "URL"),
        .value = try allocator.dupe(u8, "https://github.com"),
    });
    try arr.append(KeyValue{
        .key = try allocator.dupe(u8, "UserName"),
        .value = try allocator.dupe(u8, "max"),
    });

    const entry = Entry{
        .uuid = try Uuid.urn.deserialize("0ff2cbb1-69d5-4fda-bb68-da67291dcb07"),
        .icon_id = 0,
        .tags = try allocator.dupe(u8, "programming"),
        .times = .{
            .last_modification_time = 63860739126,
            .creation_time = 63860739100,
            .last_access_time = 63860739126,
            .expiry_time = 63860739100,
            .expires = false,
            .usage_count = 0,
            .location_changed = 63860739126,
        },
        .strings = arr,
        .auto_type = .{
            .enabled = true,
            .data_transfer_obfuscation = 0,
        },
        .allocator = allocator,
    };
    defer entry.deinit();

    var digest: [64]u8 = .{0} ** 64;
    std.crypto.hash.sha2.Sha512.hash("\xaa\xc0\x53\xb5\x37\x5b\xb0\x93\xba\xd1\xcb\x42\xae\xf1\x83\x23\xde\x86\x72\x2e\x49\x30\xa7\xac\x22\x69\x6d\x64\x24\x7b\xfc\x79\x3d\x58\xa7\x1e\xf0\x5b\x35\x52\x6f\x87\x26\xb3\x55\x57\x22\x2d\xb0\xfa\x62\x00\x2d\x6d\x5e\x96\x21\x7e\xf8\x7f\x72\x87\x13\xc7", &digest, .{});

    var chacha20 = ChaCha20.init(
        0,
        digest[0..32].*,
        digest[32..44].*,
    );

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();

    try entry.toXml(out.writer(), 0, &chacha20);

    try std.testing.expectEqualSlices(u8, expected, out.items);
}

test "serialize entry #2" {
    const allocator = std.testing.allocator;

    const expected =
        \\<Group>
        \\  <UUID>TDZnaQfoS8mAkT5crv6XEA==</UUID>
        \\  <Name>Root</Name>
        \\  <Notes/>
        \\  <IconID>48</IconID>
        \\  <Times>
        \\    <LastModificationTime>b4xl3g4AAAA=</LastModificationTime>
        \\    <CreationTime>0Itl3g4AAAA=</CreationTime>
        \\    <LastAccessTime>b4xl3g4AAAA=</LastAccessTime>
        \\    <ExpiryTime>0Itl3g4AAAA=</ExpiryTime>
        \\    <Expires>False</Expires>
        \\    <UsageCount>0</UsageCount>
        \\    <LocationChanged>0Itl3g4AAAA=</LocationChanged>
        \\  </Times>
        \\  <IsExpanded>True</IsExpanded>
        \\  <DefaultAutoTypeSequence/>
        \\  <EnableAutoType>null</EnableAutoType>
        \\  <EnableSearching>null</EnableSearching>
        \\  <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>
        \\  <Entry>
        \\    <UUID>D/LLsWnVT9q7aNpnKR3LBw==</UUID>
        \\    <IconID>0</IconID>
        \\    <ForegroundColor/>
        \\    <BackgroundColor/>
        \\    <OverrideURL/>
        \\    <Tags>programming</Tags>
        \\    <Times>
        \\      <LastModificationTime>Noxl3g4AAAA=</LastModificationTime>
        \\      <CreationTime>HIxl3g4AAAA=</CreationTime>
        \\      <LastAccessTime>Noxl3g4AAAA=</LastAccessTime>
        \\      <ExpiryTime>HIxl3g4AAAA=</ExpiryTime>
        \\      <Expires>False</Expires>
        \\      <UsageCount>0</UsageCount>
        \\      <LocationChanged>Noxl3g4AAAA=</LocationChanged>
        \\    </Times>
        \\    <String>
        \\      <Key>Notes</Key>
        \\      <Value/>
        \\    </String>
        \\    <String>
        \\      <Key>Password</Key>
        \\      <Value Protected="True">h16dtqbi</Value>
        \\    </String>
        \\    <String>
        \\      <Key>Title</Key>
        \\      <Value>Github</Value>
        \\    </String>
        \\    <String>
        \\      <Key>URL</Key>
        \\      <Value>https://github.com</Value>
        \\    </String>
        \\    <String>
        \\      <Key>UserName</Key>
        \\      <Value>max</Value>
        \\    </String>
        \\    <AutoType>
        \\      <Enabled>True</Enabled>
        \\      <DataTransferObfuscation>0</DataTransferObfuscation>
        \\      <DefaultSequence/>
        \\    </AutoType>
        \\    <History/>
        \\  </Entry>
        \\  <Entry>
        \\    <UUID>Fkt7IHIgRHGuvzAjpwSy9A==</UUID>
        \\    <IconID>0</IconID>
        \\    <ForegroundColor/>
        \\    <BackgroundColor/>
        \\    <OverrideURL/>
        \\    <Tags/>
        \\    <Times>
        \\      <LastModificationTime>b4xl3g4AAAA=</LastModificationTime>
        \\      <CreationTime>OIxl3g4AAAA=</CreationTime>
        \\      <LastAccessTime>b4xl3g4AAAA=</LastAccessTime>
        \\      <ExpiryTime>OIxl3g4AAAA=</ExpiryTime>
        \\      <Expires>False</Expires>
        \\      <UsageCount>0</UsageCount>
        \\      <LocationChanged>b4xl3g4AAAA=</LocationChanged>
        \\    </Times>
        \\    <String>
        \\      <Key>Notes</Key>
        \\      <Value/>
        \\    </String>
        \\    <String>
        \\      <Key>Password</Key>
        \\      <Value Protected="True">BY1N++nX</Value>
        \\    </String>
        \\    <String>
        \\      <Key>Title</Key>
        \\      <Value>Codeberg</Value>
        \\    </String>
        \\    <String>
        \\      <Key>URL</Key>
        \\      <Value>https://codeberg.org</Value>
        \\    </String>
        \\    <String>
        \\      <Key>UserName</Key>
        \\      <Value>max</Value>
        \\    </String>
        \\    <AutoType>
        \\      <Enabled>True</Enabled>
        \\      <DataTransferObfuscation>0</DataTransferObfuscation>
        \\      <DefaultSequence/>
        \\    </AutoType>
        \\    <History/>
        \\  </Entry>
        \\</Group>
        \\
    ;

    var entry1 = Entry{
        .uuid = try Uuid.urn.deserialize("0ff2cbb1-69d5-4fda-bb68-da67291dcb07"),
        .icon_id = 0,
        .tags = try allocator.dupe(u8, "programming"),
        .times = .{
            .last_modification_time = 63860739126,
            .creation_time = 63860739100,
            .last_access_time = 63860739126,
            .expiry_time = 63860739100,
            .expires = false,
            .usage_count = 0,
            .location_changed = 63860739126,
        },
        .strings = std.ArrayList(KeyValue).init(allocator),
        .auto_type = .{
            .enabled = true,
            .data_transfer_obfuscation = 0,
        },
        .allocator = allocator,
    };
    try entry1.set("Notes", "", false);
    try entry1.set("Password", "123456", true);
    try entry1.set("Title", "Github", false);
    try entry1.set("URL", "https://github.com", false);
    try entry1.set("UserName", "max", false);
    entry1.times = .{
        .last_modification_time = 63860739126,
        .creation_time = 63860739100,
        .last_access_time = 63860739126,
        .expiry_time = 63860739100,
        .expires = false,
        .usage_count = 0,
        .location_changed = 63860739126,
    };

    var entry2 = Entry{
        .uuid = try Uuid.urn.deserialize("164b7b20-7220-4471-aebf-3023a704b2f4"),
        .icon_id = 0,
        .tags = null,
        .times = .{
            .last_modification_time = 0x0ede658c6f,
            .creation_time = 0x0ede658c38,
            .last_access_time = 0x0ede658c6f,
            .expiry_time = 0x0ede658c38,
            .expires = false,
            .usage_count = 0,
            .location_changed = 0x0ede658c6f,
        },
        .strings = std.ArrayList(KeyValue).init(allocator),
        .auto_type = .{
            .enabled = true,
            .data_transfer_obfuscation = 0,
        },
        .allocator = allocator,
    };
    try entry2.set("Notes", "", false);
    try entry2.set("Password", "654321", true);
    try entry2.set("Title", "Codeberg", false);
    try entry2.set("URL", "https://codeberg.org", false);
    try entry2.set("UserName", "max", false);
    entry2.times = .{
        .last_modification_time = 0x0ede658c6f,
        .creation_time = 0x0ede658c38,
        .last_access_time = 0x0ede658c6f,
        .expiry_time = 0x0ede658c38,
        .expires = false,
        .usage_count = 0,
        .location_changed = 0x0ede658c6f,
    };

    var group = Group{
        .uuid = try Uuid.urn.deserialize("4c366769-07e8-4bc9-8091-3e5caefe9710"),
        .name = try allocator.dupe(u8, "Root"),
        .notes = null,
        .icon_id = 48,
        .times = .{
            .last_modification_time = 0x0ede658c6f,
            .creation_time = 0x0ede658bd0,
            .last_access_time = 0x0ede658c6f,
            .expiry_time = 0x0ede658bd0,
            .expires = false,
            .usage_count = 0,
            .location_changed = 0x0ede658bd0,
        },
        .is_expanded = true,
        .default_auto_type_sequence = null,
        .enable_auto_type = null,
        .enable_searching = null,
        .last_top_visible_entry = 0,
        .previous_parent_group = null,
        .entries = std.ArrayList(Entry).init(allocator),
        .groups = std.ArrayList(Group).init(allocator),
        .allocator = allocator,
    };
    defer group.deinit();

    try group.entries.append(entry1);
    try group.entries.append(entry2);

    var digest: [64]u8 = .{0} ** 64;
    std.crypto.hash.sha2.Sha512.hash("\xaa\xc0\x53\xb5\x37\x5b\xb0\x93\xba\xd1\xcb\x42\xae\xf1\x83\x23\xde\x86\x72\x2e\x49\x30\xa7\xac\x22\x69\x6d\x64\x24\x7b\xfc\x79\x3d\x58\xa7\x1e\xf0\x5b\x35\x52\x6f\x87\x26\xb3\x55\x57\x22\x2d\xb0\xfa\x62\x00\x2d\x6d\x5e\x96\x21\x7e\xf8\x7f\x72\x87\x13\xc7", &digest, .{});

    var chacha20 = ChaCha20.init(
        0,
        digest[0..32].*,
        digest[32..44].*,
    );

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();

    try group.toXml(out.writer(), 0, &chacha20);

    //std.debug.print("{s}\n", .{out.items});

    try std.testing.expectEqualSlices(u8, expected, out.items);
}

test "serialize Meta #1" {
    const allocator = std.testing.allocator;

    const expected =
        \\<Meta>
        \\  <Generator>KeePassXC</Generator>
        \\  <DatabaseName>Zig Database Impl</DatabaseName>
        \\  <DatabaseNameChanged>1Li13g4AAAA=</DatabaseNameChanged>
        \\  <DatabaseDescription>This is another test database for the KDBX4 Zig impl</DatabaseDescription>
        \\  <DatabaseDescriptionChanged>1Li13g4AAAA=</DatabaseDescriptionChanged>
        \\  <DefaultUserName/>
        \\  <DefaultUserNameChanged>F7i13g4AAAA=</DefaultUserNameChanged>
        \\  <MaintenanceHistoryDays>365</MaintenanceHistoryDays>
        \\  <Color/>
        \\  <MasterKeyChanged>Erm13g4AAAA=</MasterKeyChanged>
        \\  <MasterKeyChangeRec>-1</MasterKeyChangeRec>
        \\  <MasterKeyChangeForce>-1</MasterKeyChangeForce>
        \\  <MemoryProtection>
        \\    <ProtectTitle>False</ProtectTitle>
        \\    <ProtectUserName>False</ProtectUserName>
        \\    <ProtectPassword>True</ProtectPassword>
        \\    <ProtectURL>False</ProtectURL>
        \\    <ProtectNotes>False</ProtectNotes>
        \\  </MemoryProtection>
        \\  <CustomIcons>
        \\    <Icon>
        \\      <UUID>ulxWAiHcRk6rhwFNSHp0wQ==</UUID>
        \\      <LastModificationTime>gLm13g4AAAA=</LastModificationTime>
        \\      <Data>iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEnRFWHRfcV9pY29PcmlnRGVwdGgAMzLV4rjsAAAEl0lEQVRYha1XUWhbVRj+vnPTNNvaSNnuTZpkJY4ryJ1uD3UrIjL3Ioo6fRLZ08CHKjIRHfowWJbpFHzQiUN9EB8F6YNlKMM5GRsozjnRDqpgkNgmze1Nts60KW2a5PdhyXaX3LTZmu8p5//P/3/fOffk/88hOoRlWf65QmGvAPsgYgGICBkBAIrMAJgBOUng1MCWLecmJyfLneTlWhPiuh5eIhMish9AsEO9RZJfBkSS6XzevisBpmn2LhSLhwG8LiKbOiS+PTlZAvBBXzB4PJVKLXcsoL7qcREZuRtiDyEXAyLPee1Gi4CYYeyoiHwrQKwb5C6ijI98KuM4E20FxHU9vARc6ja5W0QA2OXeCdX4YZpm7xI57iYn8CeBr0hevQu+6wTGCPzWMAgQWyLHTdPsbRGwUCwebv7mJE/Y+fwL91tWGEq9CNKuOxZAXiFwgcB5kBMA/qvHXCNwcLOuh+x8/nmSx905RWSkfrgbi7x56FLNp52attu27UuNsaXrfdc0bWh0dPSvZDJZa0rMWCx2n6Zp+ampqbmGPRQK3Yta7Z+mhZUCImY6n7cJAGHD+FREXmreQ+XzPZTL5S577W+nGBwcHKpVKv8220l+ZjvOy8qyLH+9yLSiWrXWQw4AIrK9jX2/ZVl+NVco7IVHhSNZgqZdWK8ATdN+IVnwcAXnCoW9SoB9bWKP5XK5lq27U2Sz2asQedPLJ8A+VW8sLfD5/V+vl7yBwKZN3rlELAUg0mwnWZqenk51S0A6nb5OcsrDFVGNltoEh6R0SwAAQGS2xURGFF3F6NZc2dJVcgAgW3ISUAqA1wntD4VCRre44/F4AB6fGkBeAfC8MCiRx7slYHlxcY+I9Hq4bEWRn72CRORVEVnzxtQJBHjNy06Riwrk+TZBuwZDoTfWSx7W9QMi8oSnkzyvggMD3wOY9xQh8n7YMI4NDw/33ClxIpFQYcM4JMDnbabMD4icaTSjkyLySl3Vhxr5a1XkLYjsAAAC0yC/UMCPyu+/nMlkrnll3LZt2z2lUmlYAQ/XRA5AxGwnkEqdtGdnDyoA8ImcIFkGAN4IzG8WeQTk7wAgwFYRSVRFzqyUy6cSiUTLXxcAFufnx1Gr/VCr1d5ZlZxc7hE5UV/cDYQNIykiR+rDos/v305yQ6Vc/sldFzSlnp2ZnT3llTgcDj8m1eq5dsQuAUnbcY4CriLUFwy+W7/ZAECwWi4nM5nM3wGRB0keAvCRIkc39vd/1y6xz+ebaOdzsU/0BYPv3Ry6fZFIZGt1ZeUigEEAVWraM7Ztn14zqQshXV8B4Gvjzmk9PSMzMzPTngIAIGoYOysip2+KIM8COEtgXoDQo3v2HB8bG6uuIqACQPMi95FPZh3nD7fRs9BEo9FYZWXlG4jsbPZt1vXe1d59IV2vorm/kFeUpj2dy+VaOqLnac5ms5n+YHCEZJLkbU+qxcVFzxg33S1elkm+vWHjxt1e5G0FAEAqlVq2HedoD7CdSn0MoAhyIR6PV1ZlJ+dALpD8xOf3P2A7zpF0Or20hui1Yel639DQ0MBa86LRaMw0zU5f0fgfUk/VbnmdnBIAAAAASUVORK5CYII=</Data>
        \\    </Icon>
        \\  </CustomIcons>
        \\  <RecycleBinEnabled>True</RecycleBinEnabled>
        \\  <RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID>
        \\  <RecycleBinChanged>F7i13g4AAAA=</RecycleBinChanged>
        \\  <EntryTemplatesGroup>AAAAAAAAAAAAAAAAAAAAAA==</EntryTemplatesGroup>
        \\  <EntryTemplatesGroupChanged>F7i13g4AAAA=</EntryTemplatesGroupChanged>
        \\  <LastSelectedGroup>AAAAAAAAAAAAAAAAAAAAAA==</LastSelectedGroup>
        \\  <LastTopVisibleGroup>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleGroup>
        \\  <HistoryMaxItems>10</HistoryMaxItems>
        \\  <HistoryMaxSize>6291456</HistoryMaxSize>
        \\  <SettingsChanged>F7i13g4AAAA=</SettingsChanged>
        \\  <CustomData>
        \\    <Item>
        \\      <Key>KPXC_BROWSER_firefox-laptop</Key>
        \\      <Value>eJQBp6tWf0IRQnAUErVyMGH1qKEY4wxYolAeWX+64xY=</Value>
        \\      <LastModificationTime>49223g4AAAA=</LastModificationTime>
        \\    </Item>
        \\    <Item>
        \\      <Key>_CREATED_firefox-laptop</Key>
        \\      <Value>11/1/24 3:34 PM</Value>
        \\      <LastModificationTime>49223g4AAAA=</LastModificationTime>
        \\    </Item>
        \\    <Item>
        \\      <Key>_LAST_MODIFIED</Key>
        \\      <Value>Fri Nov 1 14:51:00 2024 GMT</Value>
        \\    </Item>
        \\    <Item>
        \\      <Key>KPXC_RANDOM_SLUG</Key>
        \\      <Value>91991e15f08be61d9ef66e02434a4b4a6ad0885fc87f1ada9907a8ddeaac00e944f9b17ee26b87d392d8c4a46ba90ccc5328d2c2cf54c97863dfe0fe62898c86a01f0aec9bad632e030f9e707894f9df6fc061c641e25c6135b3a6f0bf5e6f3dae95d0c033a1731be55c1bfdf1b5fa60150ffc93591ec875abfb66763a3acff3324caeea798dd9c2</Value>
        \\      <LastModificationTime>1OG23g4AAAA=</LastModificationTime>
        \\    </Item>
        \\    <Item>
        \\      <Key>KPXC_DECRYPTION_TIME_PREFERENCE</Key>
        \\      <Value>1000</Value>
        \\      <LastModificationTime>4bi13g4AAAA=</LastModificationTime>
        \\    </Item>
        \\  </CustomData>
        \\</Meta>
        \\
    ;

    var icons = std.ArrayList(Icon).init(allocator);
    try icons.append(.{
        .uuid = try Uuid.urn.deserialize("ba5c5602-21dc-464e-ab87-014d487a74c1"),
        .last_modification_time = 0x0edeb5b980,
        .data = try allocator.dupe(u8, "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00\x00\x00\x20\x00\x00\x00\x20\x08\x06\x00\x00\x00\x73\x7a\x7a\xf4\x00\x00\x00\x09\x70\x48\x59\x73\x00\x00\x0e\xc4\x00\x00\x0e\xc4\x01\x95\x2b\x0e\x1b\x00\x00\x00\x12\x74\x45\x58\x74\x5f\x71\x5f\x69\x63\x6f\x4f\x72\x69\x67\x44\x65\x70\x74\x68\x00\x33\x32\xd5\xe2\xb8\xec\x00\x00\x04\x97\x49\x44\x41\x54\x58\x85\xad\x57\x51\x68\x5b\x55\x18\xfe\xbe\x73\xd3\x34\xdb\xda\x48\xd9\xee\x4d\x9a\x64\x25\x8e\x2b\xc8\x9d\x6e\x0f\x75\x2b\x22\x32\xf7\x22\x8a\x3a\x7d\x12\xd9\xd3\xc0\x87\x2a\x32\x11\x1d\xfa\x30\x58\x96\xe9\x14\x7c\xd0\x89\x43\x7d\x10\x1f\x05\xe9\x83\x65\x28\xc3\x39\x19\x1b\x28\xce\x39\xd1\x0e\xaa\x60\x90\xd8\x26\xcd\xed\x4d\xb6\xce\xb4\x29\x6d\x9a\xe4\xf7\x61\xc9\x76\x97\xdc\xb4\xd9\x9a\xef\x29\xe7\xff\xcf\xff\x7f\xdf\x39\xf7\xe4\xff\xcf\x21\x3a\x84\x65\x59\xfe\xb9\x42\x61\xaf\x00\xfb\x20\x62\x01\x88\x08\x19\x01\x00\x8a\xcc\x00\x98\x01\x39\x49\xe0\xd4\xc0\x96\x2d\xe7\x26\x27\x27\xcb\x9d\xe4\xe5\x5a\x13\xe2\xba\x1e\x5e\x22\x13\x22\xb2\x1f\x40\xb0\x43\xbd\x45\x92\x5f\x06\x44\x92\xe9\x7c\xde\xbe\x2b\x01\xa6\x69\xf6\x2e\x14\x8b\x87\x01\xbc\x2e\x22\x9b\x3a\x24\xbe\x3d\x39\x59\x02\xf0\x41\x5f\x30\x78\x3c\x95\x4a\x2d\x77\x2c\xa0\xbe\xea\x71\x11\x19\xb9\x1b\x62\x0f\x21\x17\x03\x22\xcf\x79\xed\x46\x8b\x80\x98\x61\xec\xa8\x88\x7c\x2b\x40\xac\x1b\xe4\x2e\xa2\x8c\x8f\x7c\x2a\xe3\x38\x13\x6d\x05\xc4\x75\x3d\xbc\x04\x5c\xea\x36\xb9\x5b\x44\x00\xd8\xe5\xde\x09\xd5\xf8\x61\x9a\x66\xef\x12\x39\xee\x26\x27\xf0\x27\x81\xaf\x48\x5e\xbd\x0b\xbe\xeb\x04\xc6\x08\xfc\xd6\x30\x08\x10\x5b\x22\xc7\x4d\xd3\xec\x6d\x11\xb0\x50\x2c\x1e\x6e\xfe\xe6\x24\x4f\xd8\xf9\xfc\x0b\xf7\x5b\x56\x18\x4a\xbd\x08\xd2\xae\x3b\x16\x40\x5e\x21\x70\x81\xc0\x79\x90\x13\x00\xfe\xab\xc7\x5c\x23\x70\x70\xb3\xae\x87\xec\x7c\xfe\x79\x92\xc7\xdd\x39\x45\x64\xa4\x7e\xb8\x1b\x8b\xbc\x79\xe8\x52\xcd\xa7\x9d\x9a\xb6\xdb\xb6\xed\x4b\x8d\xb1\xa5\xeb\x7d\xd7\x34\x6d\x68\x74\x74\xf4\xaf\x64\x32\x59\x6b\x4a\xcc\x58\x2c\x76\x9f\xa6\x69\xf9\xa9\xa9\xa9\xb9\x86\x3d\x14\x0a\xdd\x8b\x5a\xed\x9f\xa6\x85\x95\x02\x22\x66\x3a\x9f\xb7\x09\x00\x61\xc3\xf8\x54\x44\x5e\x6a\xde\x43\xe5\xf3\x3d\x94\xcb\xe5\x2e\x7b\xed\x6f\xa7\x18\x1c\x1c\x1c\xaa\x55\x2a\xff\x36\xdb\x49\x7e\x66\x3b\xce\xcb\xca\xb2\x2c\x7f\xbd\xc8\xb4\xa2\x5a\xb5\xd6\x43\x0e\x00\x22\xb2\xbd\x8d\x7d\xbf\x65\x59\x7e\x35\x57\x28\xec\x85\x47\x85\x23\x59\x82\xa6\x5d\x58\xaf\x00\x4d\xd3\x7e\x21\x59\xf0\x70\x05\xe7\x0a\x85\xbd\x4a\x80\x7d\x6d\x62\x8f\xe5\x72\xb9\x96\xad\xbb\x53\x64\xb3\xd9\xab\x10\x79\xd3\xcb\x27\xc0\x3e\x55\x6f\x2c\x2d\xf0\xf9\xfd\x5f\xaf\x97\xbc\x81\xc0\xa6\x4d\xde\xb9\x44\x2c\x05\x20\xd2\x6c\x27\x59\x9a\x9e\x9e\x4e\x75\x4b\x40\x3a\x9d\xbe\x4e\x72\xca\xc3\x15\x51\x8d\x96\xda\x04\x87\xa4\x74\x4b\x00\x00\x40\x64\xb6\xc5\x44\x46\x14\x5d\xc5\xe8\xd6\x5c\xd9\xd2\x55\x72\x00\x20\x5b\x72\x12\x50\x0a\x80\xd7\x09\xed\x0f\x85\x42\x46\xb7\xb8\xe3\xf1\x78\x00\x1e\x9f\x1a\x40\x5e\x01\xf0\xbc\x30\x28\x91\xc7\xbb\x25\x60\x79\x71\x71\x8f\x88\xf4\x7a\xb8\x6c\x45\x91\x9f\xbd\x82\x44\xe4\x55\x11\x59\xf3\xc6\xd4\x09\x04\x78\xcd\xcb\x4e\x91\x8b\x0a\xe4\xf9\x36\x41\xbb\x06\x43\xa1\x37\xd6\x4b\x1e\xd6\xf5\x03\x22\xf2\x84\xa7\x93\x3c\xaf\x82\x03\x03\xdf\x03\x98\xf7\x14\x21\xf2\x7e\xd8\x30\x8e\x0d\x0f\x0f\xf7\xdc\x29\x71\x22\x91\x50\x61\xc3\x38\x24\xc0\xe7\x6d\xa6\xcc\x0f\x88\x9c\x69\x34\xa3\x93\x22\xf2\x4a\x5d\xd5\x87\x1a\xf9\x6b\x55\xe4\x2d\x88\xec\x00\x00\x02\xd3\x20\xbf\x50\xc0\x8f\xca\xef\xbf\x9c\xc9\x64\xae\x79\x65\xdc\xb6\x6d\xdb\x3d\xa5\x52\x69\x58\x01\x0f\xd7\x44\x0e\x40\xc4\x6c\x27\x90\x4a\x9d\xb4\x67\x67\x0f\x2a\x00\xf0\x89\x9c\x20\x59\x06\x00\xde\x08\xcc\x6f\x16\x79\x04\xe4\xef\x00\x20\xc0\x56\x11\x49\x54\x45\xce\xac\x94\xcb\xa7\x12\x89\x44\xcb\x5f\x17\x00\x16\xe7\xe7\xc7\x51\xab\xfd\x50\xab\xd5\xde\x59\x95\x9c\x5c\xee\x11\x39\x51\x5f\xdc\x0d\x84\x0d\x23\x29\x22\x47\xea\xc3\xa2\xcf\xef\xdf\x4e\x72\x43\xa5\x5c\xfe\xc9\x5d\x17\x34\xa5\x9e\x9d\x99\x9d\x3d\xe5\x95\x38\x1c\x0e\x3f\x26\xd5\xea\xb9\x76\xc4\x2e\x01\x49\xdb\x71\x8e\x02\xae\x22\xd4\x17\x0c\xbe\x5b\xbf\xd9\x00\x40\xb0\x5a\x2e\x27\x33\x99\xcc\xdf\x01\x91\x07\x49\x1e\x02\xf0\x91\x22\x47\x37\xf6\xf7\x7f\xd7\x2e\xb1\xcf\xe7\x9b\x68\xe7\x73\xb1\x4f\xf4\x05\x83\xef\xdd\x1c\xba\x7d\x91\x48\x64\x6b\x75\x65\xe5\x22\x80\x41\x00\x55\x6a\xda\x33\xb6\x6d\x9f\x5e\x33\xa9\x0b\x21\x5d\x5f\x01\xe0\x6b\xe3\xce\x69\x3d\x3d\x23\x33\x33\x33\xd3\x9e\x02\x00\x20\x6a\x18\x3b\x2b\x22\xa7\x6f\x8a\x20\xcf\x02\x38\x4b\x60\x5e\x80\xd0\xa3\x7b\xf6\x1c\x1f\x1b\x1b\xab\xae\x22\xa0\x02\x40\xf3\x22\xf7\x91\x4f\x66\x1d\xe7\x0f\xb7\xd1\xb3\xd0\x44\xa3\xd1\x58\x65\x65\xe5\x1b\x88\xec\x6c\xf6\x6d\xd6\xf5\xde\xd5\xde\x7d\x21\x5d\xaf\xa2\xb9\xbf\x90\x57\x94\xa6\x3d\x9d\xcb\xe5\x5a\x3a\xa2\xe7\x69\xce\x66\xb3\x99\xfe\x60\x70\x84\x64\x92\xe4\x6d\x4f\xaa\xc5\xc5\x45\xcf\x18\x37\xdd\x2d\x5e\x96\x49\xbe\xbd\x61\xe3\xc6\xdd\x5e\xe4\x6d\x05\x00\x40\x2a\x95\x5a\xb6\x1d\xe7\x68\x0f\xb0\x9d\x4a\x7d\x0c\xa0\x08\x72\x21\x1e\x8f\x57\x56\x65\x27\xe7\x40\x2e\x90\xfc\xc4\xe7\xf7\x3f\x60\x3b\xce\x91\x74\x3a\xbd\xb4\x86\xe8\xb5\x61\xe9\x7a\xdf\xd0\xd0\xd0\xc0\x5a\xf3\xa2\xd1\x68\xcc\x34\xcd\x4e\x5f\xd1\xf8\x1f\x52\x4f\xd5\x6e\x79\x9d\x9c\x12\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82"),
    });

    var data = std.ArrayList(KeyValue).init(allocator);
    try data.append(.{
        .key = try allocator.dupe(u8, "KPXC_BROWSER_firefox-laptop"),
        .value = try allocator.dupe(u8, "eJQBp6tWf0IRQnAUErVyMGH1qKEY4wxYolAeWX+64xY="),
        .last_modification_time = 0x0edeb6dde3,
    });
    try data.append(.{
        .key = try allocator.dupe(u8, "_CREATED_firefox-laptop"),
        .value = try allocator.dupe(u8, "11/1/24 3:34 PM"),
        .last_modification_time = 0x0edeb6dde3,
    });
    try data.append(.{
        .key = try allocator.dupe(u8, "_LAST_MODIFIED"),
        .value = try allocator.dupe(u8, "Fri Nov 1 14:51:00 2024 GMT"),
    });
    try data.append(.{
        .key = try allocator.dupe(u8, "KPXC_RANDOM_SLUG"),
        .value = try allocator.dupe(u8, "91991e15f08be61d9ef66e02434a4b4a6ad0885fc87f1ada9907a8ddeaac00e944f9b17ee26b87d392d8c4a46ba90ccc5328d2c2cf54c97863dfe0fe62898c86a01f0aec9bad632e030f9e707894f9df6fc061c641e25c6135b3a6f0bf5e6f3dae95d0c033a1731be55c1bfdf1b5fa60150ffc93591ec875abfb66763a3acff3324caeea798dd9c2"),
        .last_modification_time = 0x0edeb6e1d4,
    });
    try data.append(.{
        .key = try allocator.dupe(u8, "KPXC_DECRYPTION_TIME_PREFERENCE"),
        .value = try allocator.dupe(u8, "1000"),
        .last_modification_time = 0x0edeb5b8e1,
    });

    var meta = Meta{
        .generator = try allocator.dupe(u8, "KeePassXC"),
        .database_name = try allocator.dupe(u8, "Zig Database Impl"),
        .database_name_changed = 0x0edeb5b8d4,
        .database_description = try allocator.dupe(u8, "This is another test database for the KDBX4 Zig impl"),
        .database_description_changed = 0x0edeb5b8d4,
        .default_user_name_changed = 0x0edeb5b817,
        .maintenance_history_days = 365,
        .master_key_changed = 0x0edeb5b912,
        .master_key_change_rec = -1,
        .master_key_change_force = -1,
        .memory_protection = .{},
        .custom_icons = icons,
        .recycle_bin_enabled = true,
        .recycle_bin_uuid = 0,
        .recycle_bin_changed = 0x0edeb5b817,
        .entry_template_group = 0,
        .entry_template_group_changed = 0x0edeb5b817,
        .last_selected_group = 0,
        .last_top_visible_group = 0,
        .history_max_items = 10,
        .history_max_size = 6291456,
        .settings_changed = 0x0edeb5b817,
        .custom_data = data,
        .allocator = allocator,
    };
    defer meta.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();

    try meta.toXml(out.writer(), 0);

    //std.debug.print("{s}\n", .{out.items});

    try std.testing.expectEqualSlices(u8, expected, out.items);
}

test "create new database #1" {
    const allocator = std.testing.allocator;

    const database = try Database.newDatabase(.{
        .password = "1234",
        .allocator = allocator,
    });
    defer allocator.free(database);

    //    var file = try std.fs.cwd().createFile("foo.kdbx", .{});
    //    defer file.close();
    //
    //    try file.writeAll(database);
    //
    //    // ------------------------------------
    //
    var fbs = std.io.fixedBufferStream(database);
    const reader = fbs.reader();

    const header = try Header.readAlloc(reader, std.testing.allocator);
    defer header.deinit();

    var db_key = DatabaseKey{
        .password = try std.testing.allocator.dupe(u8, "1234"),
        .allocator = std.testing.allocator,
    };
    defer db_key.deinit();
    var keys = try header.deriveKeys(db_key);
    defer keys.deinit();
    try header.checkMac(&keys);

    var body = try Body.readAlloc(reader, &header, &keys, std.testing.allocator);
    defer body.deinit();

    try std.testing.expectEqual(InnerHeader.StreamCipher.ChaCha20, body.inner_header.stream_cipher);

    //std.debug.print("{s}\n", .{body.xml});

    const body_xml = try body.getXml(std.testing.allocator);
    defer body_xml.deinit();
}
