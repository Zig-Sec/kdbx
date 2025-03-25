const std = @import("std");

// https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
// OIDS: https://oidref.com/1.2.840.10045.3.1.7 and https://www.rfc-editor.org/rfc/rfc3279

pub const AsymmetricKeyPairTag = enum {
    EcdsaP256Sha256,
};

pub const AsymmetricKeyPair = union(AsymmetricKeyPairTag) {
    EcdsaP256Sha256: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
};

pub fn asn1FromKey(key: anytype, allocator: std.mem.Allocator) ![]const u8 {
    const T = @TypeOf(key);

    if (T == std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey) {
        return error.UnsupportedKeyType;
    } else if (T == std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair) {
        // asn.1 template for es256 keys
        const template = "\x30\x81\x87\x02\x01\x00\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x04\x6d\x30\x6b\x02\x01\x01\x04\x20{s}\xa1\x44\x03\x42\x00\x04{s}{s}";
        const k: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair = key;
        const dhex = k.secret_key.toBytes();
        const sec1 = k.public_key.toUncompressedSec1();

        return try std.fmt.allocPrint(allocator, template, .{
            dhex,
            sec1[1..33],
            sec1[33..65],
        });
    } else {
        return error.UnsupportedKeyType;
    }
}

pub fn pemFromKey(key: anytype, allocator: std.mem.Allocator) ![]const u8 {
    const asn1 = try asn1FromKey(key, allocator);
    defer allocator.free(asn1);

    const b64 = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(asn1.len));
    defer allocator.free(b64);
    _ = std.base64.standard.Encoder.encode(b64, asn1);

    var arr = std.ArrayList(u8).init(allocator);
    errdefer arr.deinit();

    try arr.appendSlice("-----BEGIN PRIVATE KEY-----\n");

    var i: usize = 0;
    while (i < b64.len) {
        const l = if (i + 64 > b64.len) b64.len - i else 64;

        try arr.appendSlice(b64[i .. i + l]);
        try arr.append('\n');

        i += l;
    }

    try arr.appendSlice("-----END PRIVATE KEY-----\n");

    return try arr.toOwnedSlice();
}

pub fn asymmetricKeyPairFromPem(pem: []const u8, allocator: std.mem.Allocator) !AsymmetricKeyPair {
    var iter = std.mem.splitAny(u8, pem, "\n");

    const begin = iter.next();
    if (begin == null) return error.UnexpectedEndOfInput;
    if (!std.mem.containsAtLeast(u8, begin.?, 1, "BEGIN PRIVATE KEY"))
        return error.IsNotAPrivateKey;

    var data = std.ArrayList(u8).init(allocator);
    defer data.deinit();

    while (iter.next()) |d| {
        if (std.mem.containsAtLeast(u8, d, 1, "END PRIVATE KEY")) break;

        try data.appendSlice(d);
    }

    const l = try std.base64.standard.Decoder.calcSizeForSlice(data.items);
    const decoded = try allocator.alloc(u8, l);
    defer allocator.free(decoded);

    try std.base64.standard.Decoder.decode(decoded, data.items);

    return try asymmetricKeyPairFromAsn1(decoded);
}

pub fn asymmetricKeyPairFromAsn1(asn1: []const u8) !AsymmetricKeyPair {
    // https://www.rfc-editor.org/rfc/rfc5958#section-2
    // OneAsymmetricKey ::= SEQUENCE {
    //   version                   Version,
    //   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
    //   privateKey                PrivateKey,
    //   attributes            [0] Attributes OPTIONAL,
    //   ...,
    //   [[2: publicKey        [1] PublicKey OPTIONAL ]],
    //   ...
    // }

    const tv = try TagValue.fromRaw(asn1);
    if (tv.tag != .sequence) return error.ExpectedSequence;

    var iter = try tv.getSequence();

    const version_ = iter.next();
    if (version_ == null) return error.ExpectedVersion;
    const version = try version_.?.getInteger(u64);
    // 0 = v1, 1 = v2
    if (version != 0 and version != 1) return error.UnsupportedVersion;

    const algorithm_identifiers = iter.next();
    if (algorithm_identifiers == null) return error.ExpectedAlgorithmIdentifier;
    if (algorithm_identifiers.?.tag != .sequence) return error.ExpectedSequence;

    var iter2 = try algorithm_identifiers.?.getSequence();
    const o1 = iter2.next();
    if (o1 == null) return error.ExpectedAlgorithmIdentifier;
    if (o1.?.tag != .object_identifier) return error.ExpectedOid;

    const o2 = iter2.next();
    if (o2 == null) return error.ExpectedAlgorithmIdentifier;
    if (o2.?.tag != .object_identifier) return error.ExpectedOid;

    if (o1.?.isOid("1.2.840.10045.2.1")) { // ecPublicKey

        const priv_key = iter.next();
        if (priv_key == null) return error.ExpectedEcPrivateKey;
        const inner = try priv_key.?.unwrap();
        if (inner.tag != .sequence) return error.ExpectedEcPrivateKey;

        // see https://www.rfc-editor.org/rfc/rfc5915#section-3
        var priv_key_seq = try inner.getSequence();

        const key_version_ = priv_key_seq.next();
        if (key_version_ == null) return error.ExpectedKeyVersion;
        const key_version = try key_version_.?.getInteger(u64);
        if (key_version != 1) return error.InvalidKeyVersion;

        const d = priv_key_seq.next();
        if (d == null) return error.ExpectedPrivateKey;
        if (d.?.tag != .octet_string) return error.ExpectedPrivateKey;

        if (o2.?.isOid("1.2.840.10045.3.1.7")) { // prime256v1
            const sec = d.?.getValue();
            if (sec.len != 32) return error.InvalidKeyLength;
            const key = try std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(sec[0..32].*);
            const key_pair = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(key);
            return .{
                .EcdsaP256Sha256 = key_pair,
            };
        } else {
            return error.UnsupportedCurve;
        }
    } else {
        return error.UnsupportedKeyType;
    }
}

/// A tag consists of the following: TagClass(8, 7) || Constructed?(6) || Tag(5..0)
pub const Tag = enum(u8) {
    context01 = 0x00,
    context02 = 0x01,
    integer = 0x02,
    bit_string = 0x03,
    octet_string = 0x04,
    null = 0x05,
    object_identifier = 0x06,
    context03 = 0x07,
    context04 = 0x08,
    context05 = 0x09,
    context06 = 0x0a,
    context07 = 0x0b,
    utf8string = 0x0c,
    sequence = 0x10,
    set = 0x11,
    printable_string = 0x13,
    ia5string = 0x16,
    utctime = 0x17,
    generalized_time = 0x18,

    pub const ToByteOptions = struct {
        constructed: bool = false,
        class: TagClass = .universal,
    };

    pub fn toByte(self: @This(), options: ToByteOptions) u8 {
        var b: u8 = @intFromEnum(self);
        if (options.constructed) b |= (1 < 5);
        return options.class.add(b);
    }

    pub fn fromByte(b: u8) !@This() {
        return switch (b & 0x1f) {
            0x00 => .context01,
            0x01 => .context02,
            0x02 => .integer,
            0x03 => .bit_string,
            0x04 => .octet_string,
            0x05 => .null,
            0x06 => .object_identifier,
            0x07 => .context03,
            0x08 => .context04,
            0x09 => .context05,
            0x0a => .context06,
            0x0b => .context07,
            0x0c => .utf8string,
            0x10 => .sequence,
            0x11 => .set,
            0x13 => .printable_string,
            0x16 => .ia5string,
            0x17 => .utctime,
            0x18 => .generalized_time,
            else => error.NoSuchTag,
        };
    }
};

pub const TagClass = enum {
    universal,
    application,
    context_specific,
    private,

    pub fn fromByte(b: u8) @This() {
        return switch (b >> 6) {
            0 => .universal,
            1 => .application,
            2 => .context_specific,
            3 => .private,
            else => unreachable,
        };
    }

    pub fn add(self: @This(), b: u8) u8 {
        return switch (self) {
            .application => b | (1 << 6),
            .context_specific => b | (2 << 6),
            .private => b | (3 << 6),
            .universal => b,
        };
    }
};

pub const OID = enum {
    // Public Key Types - https://oidref.com/1.2.840.10045.2
    // https://www.rfc-editor.org/rfc/rfc5958
    /// 1.2.840.10045.2.1
    ecPublicKey,
    // Curves
    /// Elliptic curve domain "secp192r1" listed in "SEC 2" recommended elliptic curve domain
    prime192v1,
    /// Prime 192 V2
    prime192v2,
    /// Prime 192 V3
    prime192v3,
    /// Prime 239v1
    prime239v1,
    /// Prime 239v2
    prime239v2,
    /// Prime 239v3
    prime239v3,
    /// 1.2.840.10045.3.1.7 - https://oidref.com/1.2.840.10045.3.1
    /// https://www.rfc-editor.org/rfc/rfc5915
    prime256v1,
};

pub const TagValue = struct {
    tag: Tag,
    tag_class: TagClass,
    constructed: bool = false,
    value: []const u8,
    // The total size in bytes used by this object,
    // including the tag, length and value.
    total_size: usize,

    pub fn fromRaw(s: []const u8) !@This() {
        if (s.len < 2) return error.UnexpectedEndOfInput;
        var total_size: usize = 0;

        const tag = try Tag.fromByte(s[0]);
        const tag_class = TagClass.fromByte(s[0]);
        total_size += 1;

        const len = if (lengthIsLong(s[1])) blk: {
            const l = getLongLength(s[1]);
            if (l + 2 > s.len) return error.UnexpectedEndOfInput;
            if (@sizeOf(usize) < l) return error.LengthTooLarge;

            // length is encoded in big-endian
            const raw_len = s[2 .. l + 2];

            var len: usize = 0;
            for (raw_len) |d| {
                len <<= 8;
                len |= @as(usize, @intCast(d));
            }

            total_size += 1 + l;
            break :blk len;
        } else blk: {
            total_size += 1;
            break :blk getLongLength(s[1]);
        };

        if (total_size + len > s.len) return error.UnexpectedEndOfInput;
        const value = s[total_size .. total_size + len];
        total_size += len;

        return .{
            .tag = tag,
            .tag_class = tag_class,
            .constructed = if (s[0] & 0b00100000 != 0) true else false,
            .value = value,
            .total_size = total_size,
        };
    }

    pub fn getSequence(self: *const @This()) !SequenceIterator {
        return .{
            .s = self.value,
        };
    }

    pub fn unwrap(self: *const @This()) !@This() {
        return @This().fromRaw(self.value);
    }

    // TODO: currently supports only positive numbers
    pub fn getInteger(self: *const @This(), T: anytype) !u64 {
        if (self.tag != .integer) return error.IsNotAnInteger;

        const s = @sizeOf(T);
        if (s < self.value.len) return error.IntegerTypeTooSmall;

        var v: T = 0;
        for (self.value) |d| {
            v <<= 8;
            v |= @as(T, @intCast(d));
        }

        return v;
    }

    pub fn isOid(self: *const @This(), oid: []const u8) bool {
        var id_buffer: [16]u8 = .{10} ** 16;
        const id = oidToSlice(&id_buffer, oid) catch return false;
        return std.mem.eql(u8, self.value, id_buffer[0..id]);
    }

    // Return the raw value.
    pub fn getValue(self: *const @This()) []const u8 {
        return self.value;
    }

    pub const SequenceIterator = struct {
        i: usize = 0,
        s: []const u8,

        pub fn next(self: *@This()) ?TagValue {
            if (self.i >= self.s.len) return null;
            const tv = TagValue.fromRaw(self.s[self.i..]) catch |e| {
                std.log.err("{any}", .{e});
                return null;
            };
            self.i += tv.total_size;
            return tv;
        }
    };
};

fn lengthIsLong(b: u8) bool {
    return (b & 0x80) != 0;
}

fn getLongLength(b: u8) usize {
    return @intCast(b & 0x7f);
}

pub fn oidToSlice(slice: []u8, oid: []const u8) !usize {
    var i: usize = 0;
    var iter = std.mem.splitAny(u8, oid, ".");

    if (slice.len < 1) return error.SliceTooSmall;

    // Parse first two numbers
    const c1s = iter.next();
    const c2s = iter.next();
    if (c1s == null or c2s == null) return error.InvalidOid;

    const c1 = try std.fmt.parseInt(u8, c1s.?, 0);
    const c2 = try std.fmt.parseInt(u8, c2s.?, 0);

    slice[i] = 40 * c1 + c2;
    i += 1;

    // Parse everything else...
    while (iter.next()) |v| {
        // We limit ourselves to 64 bit integers
        var c = try std.fmt.parseInt(u64, v, 0);

        var j: usize = 0;
        while (c > 0) {
            var l: u8 = @intCast(0x7f & c);
            if (j > 0) l |= 0x80;
            slice[i + j] = l;

            c >>= 7;
            j += 1;
        }

        // little to big-endian
        std.mem.reverse(u8, slice[i .. i + j]);
        i += j;
    }

    return i;
}

test "encode ecPublicKey OID" {
    var oid_slice: [7]u8 = .{0} ** 7;
    const expected_oid = "\x2a\x86\x48\xce\x3d\x02\x01";

    try std.testing.expectEqual(@as(usize, 7), try oidToSlice(&oid_slice, "1.2.840.10045.2.1"));
    try std.testing.expectEqualSlices(u8, expected_oid, &oid_slice);
}

test "encode prime256v1 OID" {
    var oid_slice: [8]u8 = .{0} ** 8;
    const expected_oid = "\x2a\x86\x48\xce\x3d\x03\x01\x07";

    try std.testing.expectEqual(@as(usize, 8), try oidToSlice(&oid_slice, "1.2.840.10045.3.1.7"));
    try std.testing.expectEqualSlices(u8, expected_oid, &oid_slice);
}

test "decode private key #1" {
    const k = "\x30\x81\x87\x02\x01\x00\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x04\x6d\x30\x6b\x02\x01\x01\x04\x20\x7d\x55\xd4\xac\x0d\xbd\xa7\x62\xe7\xa8\x2d\xd3\x07\xfa\xa2\x9d\xd9\x8d\x57\xec\xbe\xeb\xe0\xa7\xe4\x0c\x07\xfe\x3d\xc8\xcf\x4f\xa1\x44\x03\x42\x00\x04\x11\x28\xbb\xa8\xc7\x7e\xf1\x95\x31\xe7\xba\x64\xb2\xbd\x33\x25\x1e\x1d\x55\x30\xbd\x9e\x4b\x1b\x58\xc1\xc7\x80\xfe\x9a\xb5\x81\x23\x37\x5c\xe4\x67\x5f\x09\xec\x70\xd0\x5a\x10\x91\xbc\xd4\x72\x69\xeb\xe4\xf9\x32\x28\xa6\x3e\xdb\x3b\x57\x05\x23\xf4\x6d\x2c";

    const tv = try TagValue.fromRaw(k);
    try std.testing.expectEqual(Tag.sequence, tv.tag);
    try std.testing.expectEqualSlices(u8, "\x02\x01\x00\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x04\x6d\x30\x6b\x02\x01\x01\x04\x20\x7d\x55\xd4\xac\x0d\xbd\xa7\x62\xe7\xa8\x2d\xd3\x07\xfa\xa2\x9d\xd9\x8d\x57\xec\xbe\xeb\xe0\xa7\xe4\x0c\x07\xfe\x3d\xc8\xcf\x4f\xa1\x44\x03\x42\x00\x04\x11\x28\xbb\xa8\xc7\x7e\xf1\x95\x31\xe7\xba\x64\xb2\xbd\x33\x25\x1e\x1d\x55\x30\xbd\x9e\x4b\x1b\x58\xc1\xc7\x80\xfe\x9a\xb5\x81\x23\x37\x5c\xe4\x67\x5f\x09\xec\x70\xd0\x5a\x10\x91\xbc\xd4\x72\x69\xeb\xe4\xf9\x32\x28\xa6\x3e\xdb\x3b\x57\x05\x23\xf4\x6d\x2c", tv.value);

    var iter = try tv.getSequence();

    const version = iter.next();
    try std.testing.expect(version != null);
    try std.testing.expectEqual(Tag.integer, version.?.tag);
    try std.testing.expectEqualSlices(u8, "\x00", version.?.value);
    try std.testing.expectEqual(@as(usize, 0), try version.?.getInteger(usize));

    const algorithm_identifiers = iter.next();
    try std.testing.expect(algorithm_identifiers != null);
    try std.testing.expectEqual(Tag.sequence, algorithm_identifiers.?.tag);

    {
        var iter2 = try algorithm_identifiers.?.getSequence();

        const o1 = iter2.next();
        try std.testing.expect(o1 != null);
        try std.testing.expectEqual(Tag.object_identifier, o1.?.tag);
        try std.testing.expect(o1.?.isOid("1.2.840.10045.2.1"));

        const o2 = iter2.next();
        try std.testing.expect(o2 != null);
        try std.testing.expectEqual(Tag.object_identifier, o2.?.tag);
        try std.testing.expect(o2.?.isOid("1.2.840.10045.3.1.7"));
    }

    const priv_key = iter.next();
    try std.testing.expect(priv_key != null);
    try std.testing.expectEqual(Tag.octet_string, priv_key.?.tag);

    const inner = try priv_key.?.unwrap();
    try std.testing.expectEqual(Tag.sequence, inner.tag);

    {
        // see https://www.rfc-editor.org/rfc/rfc5915#section-3
        var priv_key_seq = try inner.getSequence();

        const key_version = priv_key_seq.next();
        try std.testing.expect(key_version != null);
        try std.testing.expectEqual(Tag.integer, key_version.?.tag);
        try std.testing.expectEqual(@as(usize, 1), try key_version.?.getInteger(usize));

        const d = priv_key_seq.next();
        try std.testing.expect(d != null);
        try std.testing.expectEqual(Tag.octet_string, d.?.tag);
        try std.testing.expectEqualSlices(u8, "\x7d\x55\xd4\xac\x0d\xbd\xa7\x62\xe7\xa8\x2d\xd3\x07\xfa\xa2\x9d\xd9\x8d\x57\xec\xbe\xeb\xe0\xa7\xe4\x0c\x07\xfe\x3d\xc8\xcf\x4f", d.?.getValue());

        const opt1 = priv_key_seq.next();
        try std.testing.expect(opt1 != null);
        try std.testing.expectEqual(Tag.context02, opt1.?.tag);
        try std.testing.expectEqual(TagClass.context_specific, opt1.?.tag_class);

        const xy = try opt1.?.unwrap();
        try std.testing.expectEqual(Tag.bit_string, xy.tag);
        // unused_bits(00) || uncompressed(04) || x || y
        try std.testing.expectEqualSlices(u8, "\x00\x04\x11\x28\xbb\xa8\xc7\x7e\xf1\x95\x31\xe7\xba\x64\xb2\xbd\x33\x25\x1e\x1d\x55\x30\xbd\x9e\x4b\x1b\x58\xc1\xc7\x80\xfe\x9a\xb5\x81\x23\x37\x5c\xe4\x67\x5f\x09\xec\x70\xd0\x5a\x10\x91\xbc\xd4\x72\x69\xeb\xe4\xf9\x32\x28\xa6\x3e\xdb\x3b\x57\x05\x23\xf4\x6d\x2c", xy.getValue());
    }
}

test "parse asn.1 into EcdsaP256Sha256" {
    const k = "\x30\x81\x87\x02\x01\x00\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x04\x6d\x30\x6b\x02\x01\x01\x04\x20\x7d\x55\xd4\xac\x0d\xbd\xa7\x62\xe7\xa8\x2d\xd3\x07\xfa\xa2\x9d\xd9\x8d\x57\xec\xbe\xeb\xe0\xa7\xe4\x0c\x07\xfe\x3d\xc8\xcf\x4f\xa1\x44\x03\x42\x00\x04\x11\x28\xbb\xa8\xc7\x7e\xf1\x95\x31\xe7\xba\x64\xb2\xbd\x33\x25\x1e\x1d\x55\x30\xbd\x9e\x4b\x1b\x58\xc1\xc7\x80\xfe\x9a\xb5\x81\x23\x37\x5c\xe4\x67\x5f\x09\xec\x70\xd0\x5a\x10\x91\xbc\xd4\x72\x69\xeb\xe4\xf9\x32\x28\xa6\x3e\xdb\x3b\x57\x05\x23\xf4\x6d\x2c";

    const kp = try asymmetricKeyPairFromAsn1(k);

    try std.testing.expectEqualSlices(u8, "\x7d\x55\xd4\xac\x0d\xbd\xa7\x62\xe7\xa8\x2d\xd3\x07\xfa\xa2\x9d\xd9\x8d\x57\xec\xbe\xeb\xe0\xa7\xe4\x0c\x07\xfe\x3d\xc8\xcf\x4f", kp.EcdsaP256Sha256.secret_key.toBytes()[0..]);
}

test "parse PEM into EcdsaP256Sha256" {
    const k = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfVXUrA29p2LnqC3T\nB/qindmNV+y+6+Cn5AwH/j3Iz0+hRANCAAQRKLuox37xlTHnumSyvTMlHh1VML2e\nSxtYwceA/pq1gSM3XORnXwnscNBaEJG81HJp6+T5MiimPts7VwUj9G0s\n-----END PRIVATE KEY-----\n";

    const kp = try asymmetricKeyPairFromPem(k, std.testing.allocator);

    try std.testing.expectEqualSlices(u8, "\x7d\x55\xd4\xac\x0d\xbd\xa7\x62\xe7\xa8\x2d\xd3\x07\xfa\xa2\x9d\xd9\x8d\x57\xec\xbe\xeb\xe0\xa7\xe4\x0c\x07\xfe\x3d\xc8\xcf\x4f", kp.EcdsaP256Sha256.secret_key.toBytes()[0..]);
}

test "serialize es256 key pair to asn.1" {
    const expected = "\x30\x81\x87\x02\x01\x00\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x04\x6d\x30\x6b\x02\x01\x01\x04\x20\x7d\x55\xd4\xac\x0d\xbd\xa7\x62\xe7\xa8\x2d\xd3\x07\xfa\xa2\x9d\xd9\x8d\x57\xec\xbe\xeb\xe0\xa7\xe4\x0c\x07\xfe\x3d\xc8\xcf\x4f\xa1\x44\x03\x42\x00\x04\x11\x28\xbb\xa8\xc7\x7e\xf1\x95\x31\xe7\xba\x64\xb2\xbd\x33\x25\x1e\x1d\x55\x30\xbd\x9e\x4b\x1b\x58\xc1\xc7\x80\xfe\x9a\xb5\x81\x23\x37\x5c\xe4\x67\x5f\x09\xec\x70\xd0\x5a\x10\x91\xbc\xd4\x72\x69\xeb\xe4\xf9\x32\x28\xa6\x3e\xdb\x3b\x57\x05\x23\xf4\x6d\x2c";

    const d = try std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes("\x7d\x55\xd4\xac\x0d\xbd\xa7\x62\xe7\xa8\x2d\xd3\x07\xfa\xa2\x9d\xd9\x8d\x57\xec\xbe\xeb\xe0\xa7\xe4\x0c\x07\xfe\x3d\xc8\xcf\x4f".*);
    const kp = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(d);
    const asn1 = try asn1FromKey(kp, std.testing.allocator);
    defer std.testing.allocator.free(asn1);

    try std.testing.expectEqualSlices(u8, expected, asn1);
}

test "serialize es256 key pair to pem" {
    const expected = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfVXUrA29p2LnqC3T\nB/qindmNV+y+6+Cn5AwH/j3Iz0+hRANCAAQRKLuox37xlTHnumSyvTMlHh1VML2e\nSxtYwceA/pq1gSM3XORnXwnscNBaEJG81HJp6+T5MiimPts7VwUj9G0s\n-----END PRIVATE KEY-----\n";

    const d = try std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes("\x7d\x55\xd4\xac\x0d\xbd\xa7\x62\xe7\xa8\x2d\xd3\x07\xfa\xa2\x9d\xd9\x8d\x57\xec\xbe\xeb\xe0\xa7\xe4\x0c\x07\xfe\x3d\xc8\xcf\x4f".*);
    const kp = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(d);
    const pem = try pemFromKey(kp, std.testing.allocator);
    defer std.testing.allocator.free(pem);

    try std.testing.expectEqualSlices(u8, expected, pem);
}
