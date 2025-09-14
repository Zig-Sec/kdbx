const std = @import("std");

// Why not just use fucking EPOCH
const TIME_DIFF_KDBX_EPOCH_IN_SEC = 62135600008;

pub fn decode(T: type, arr: anytype) T {
    const bytes = @typeInfo(T).int.bits / 8;
    var tmp: T = 0;

    for (0..bytes) |i| {
        tmp <<= 8;
        tmp += arr[bytes - (i + 1)];
    }

    return tmp;
}

pub fn encode(comptime n: usize, int: anytype) [n]u8 {
    var tmp: [n]u8 = undefined;

    inline for (0..n) |i| {
        tmp[i] = @intCast((int >> (@as(u5, @intCast(i)) * 8)) & 0xff);
    }

    return tmp;
}

pub fn encode2(out: *std.Io.Writer, l: usize, v: anytype) !void {
    var v2: @TypeOf(v) = v;

    for (0..l) |_| {
        try out.writeByte(@as(u8, @intCast(v2 & 0xff)));
        v2 >>= 8;
    }
}

pub fn currTime() i64 {
    return std.time.timestamp() + TIME_DIFF_KDBX_EPOCH_IN_SEC;
}
