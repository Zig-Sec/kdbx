const std = @import("std");

const BitWriter = @import("gzip/BitWriter.zig");
const huffman_encoder = @import("gzip/huffman_encoder.zig");
const huffman_decoder = @import("gzip/huffman_decoder.zig");
const container = @import("gzip/container.zig");
const Token = @import("gzip/Token.zig");
const block_writer = @import("gzip/block_writer.zig");
const Lookup = @import("gzip/Lookup.zig");
const SlidingWindow = @import("gzip/SlidingWindow.zig");
const deflate = @import("gzip/deflate.zig");
const CircularBuffer = @import("gzip/CircularBuffer.zig");
//const inflate = @import("gzip/inflate.zig");
const bit_reader = @import("gzip/bit_reader.zig");

/// Compression level, trades between speed and compression size.
pub const Options = deflate.Options;

/// Compress plain data from reader and write compressed data to the writer.
pub fn compress(reader: *std.Io.Reader, writer: *std.Io.Writer, options: Options) !void {
    try deflate.compress(.gzip, reader, writer, options);
}

/// Compressor type
pub fn Compressor(comptime WriterType: type) type {
    return deflate.Compressor(.gzip, WriterType);
}

/// Create Compressor which outputs compressed data to the writer.
pub fn compressor(writer: *std.Io.Writer, options: Options) !Compressor(@TypeOf(writer)) {
    return try deflate.compressor(.gzip, writer, options);
}

/// Huffman only compression. Without Lempel-Ziv match searching. Faster
/// compression, less memory requirements but bigger compressed sizes.
pub const huffman = struct {
    pub fn compress(reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
        try deflate.huffman.compress(.gzip, reader, writer);
    }

    pub fn Compressor(comptime WriterType: type) type {
        return deflate.huffman.Compressor(.gzip, WriterType);
    }

    pub fn compressor(writer: *std.Io.Writer) !huffman.Compressor(@TypeOf(writer)) {
        return deflate.huffman.compressor(.gzip, writer);
    }
};

// No compression store only. Compressed size is slightly bigger than plain.
pub const store = struct {
    pub fn compress(reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
        try deflate.store.compress(.gzip, reader, writer);
    }

    pub fn Compressor(comptime WriterType: type) type {
        return deflate.store.Compressor(.gzip, WriterType);
    }

    pub fn compressor(writer: *std.Io.Writer) !store.Compressor(@TypeOf(writer)) {
        return deflate.store.compressor(.gzip, writer);
    }
};

test {
    _ = BitWriter;
    _ = huffman_encoder;
    _ = huffman_decoder;
    _ = container;
    _ = Token;
    _ = block_writer;
    _ = Lookup;
    _ = SlidingWindow;
    _ = deflate;
    _ = CircularBuffer;
    //_ = inflate;
    _ = bit_reader;
}
