const std = @import("std");
const Allocator = std.mem.Allocator;

password: ?[]u8 = null,
keyfile: ?[]u8 = null,
keyprovider: ?[]u8 = null,
allocator: Allocator,

pub fn deinit(self: *const @This()) void {
    if (self.password) |d| {
        std.crypto.utils.secureZero(u8, d);
        self.allocator.free(d);
    }
    if (self.keyfile) |d| {
        std.crypto.utils.secureZero(u8, d);
        self.allocator.free(d);
    }
    if (self.keyprovider) |d| {
        std.crypto.utils.secureZero(u8, d);
        self.allocator.free(d);
    }
}
