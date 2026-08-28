const std = @import("std");

pub const Error = error{
    InvalidLength,
    InvalidEncoding,
};

pub fn maxEncodedLength(scalar_len: usize) Error!usize {
    if (scalar_len == 0 or scalar_len > 66) return error.InvalidLength;
    const content = 2 * (2 + scalar_len + 1);
    return 1 + lengthSize(content) + content;
}

/// Encodes fixed-width unsigned `r || s` as one canonical DER ECDSA signature.
/// The output is not modified unless it is large enough for the complete result.
pub fn encode(raw: []const u8, scalar_len: usize, output: []u8) Error!usize {
    if (scalar_len == 0 or scalar_len > 66 or raw.len != scalar_len * 2)
        return error.InvalidLength;

    const r = integerEncoding(raw[0..scalar_len]);
    const s = integerEncoding(raw[scalar_len..]);
    const content_len = 2 + r.len() + 2 + s.len();
    const total_len = 1 + lengthSize(content_len) + content_len;
    if (output.len < total_len) return error.InvalidLength;

    var index: usize = 0;
    output[index] = 0x30;
    index += 1;
    index += writeLength(output[index..], content_len);
    index += writeInteger(output[index..], r);
    index += writeInteger(output[index..], s);
    std.debug.assert(index == total_len);
    return total_len;
}

/// Decodes one canonical DER ECDSA signature into fixed-width unsigned `r || s`.
/// `raw_output` is unchanged on every error.
pub fn decode(der: []const u8, scalar_len: usize, raw_output: []u8) Error!void {
    if (scalar_len == 0 or scalar_len > 66 or raw_output.len != scalar_len * 2)
        return error.InvalidLength;
    if (der.len < 2 or der[0] != 0x30) return error.InvalidEncoding;

    var cursor: usize = 1;
    const sequence_len = try readLength(der, &cursor);
    const sequence_end = std.math.add(usize, cursor, sequence_len) catch
        return error.InvalidEncoding;
    if (sequence_end != der.len) return error.InvalidEncoding;

    var temporary: [132]u8 = [_]u8{0} ** 132;
    try readInteger(der, &cursor, sequence_end, temporary[0..scalar_len]);
    try readInteger(der, &cursor, sequence_end, temporary[scalar_len .. scalar_len * 2]);
    if (cursor != sequence_end) return error.InvalidEncoding;
    @memcpy(raw_output, temporary[0 .. scalar_len * 2]);
}

const IntegerView = struct {
    magnitude: []const u8,
    sign_padding: bool,

    fn len(self: IntegerView) usize {
        return self.magnitude.len + @intFromBool(self.sign_padding);
    }
};

fn integerEncoding(fixed: []const u8) IntegerView {
    var first: usize = 0;
    while (first + 1 < fixed.len and fixed[first] == 0) : (first += 1) {}
    const magnitude = fixed[first..];
    return .{
        .magnitude = magnitude,
        .sign_padding = magnitude[0] & 0x80 != 0,
    };
}

fn writeInteger(output: []u8, value: IntegerView) usize {
    output[0] = 0x02;
    output[1] = @intCast(value.len());
    var index: usize = 2;
    if (value.sign_padding) {
        output[index] = 0;
        index += 1;
    }
    @memcpy(output[index .. index + value.magnitude.len], value.magnitude);
    return index + value.magnitude.len;
}

fn lengthSize(len: usize) usize {
    return if (len < 128) 1 else 2;
}

fn writeLength(output: []u8, len: usize) usize {
    if (len < 128) {
        output[0] = @intCast(len);
        return 1;
    }
    std.debug.assert(len <= 255);
    output[0] = 0x81;
    output[1] = @intCast(len);
    return 2;
}

fn readLength(input: []const u8, cursor: *usize) Error!usize {
    if (cursor.* >= input.len) return error.InvalidEncoding;
    const first = input[cursor.*];
    cursor.* += 1;
    if (first & 0x80 == 0) return first;
    const count: usize = first & 0x7f;
    if (count == 0 or count > @sizeOf(usize)) return error.InvalidEncoding;
    const end = std.math.add(usize, cursor.*, count) catch return error.InvalidEncoding;
    if (end > input.len or input[cursor.*] == 0) return error.InvalidEncoding;
    var value: usize = 0;
    while (cursor.* < end) : (cursor.* += 1) {
        value = std.math.mul(usize, value, 256) catch return error.InvalidEncoding;
        value = std.math.add(usize, value, input[cursor.*]) catch return error.InvalidEncoding;
    }
    if (value < 128) return error.InvalidEncoding;
    return value;
}

fn readInteger(
    input: []const u8,
    cursor: *usize,
    limit: usize,
    destination: []u8,
) Error!void {
    if (cursor.* >= limit or input[cursor.*] != 0x02) return error.InvalidEncoding;
    cursor.* += 1;
    const encoded_len = try readLength(input[0..limit], cursor);
    if (encoded_len == 0) return error.InvalidEncoding;
    const end = std.math.add(usize, cursor.*, encoded_len) catch return error.InvalidEncoding;
    if (end > limit) return error.InvalidEncoding;

    const encoded = input[cursor.*..end];
    cursor.* = end;
    if (encoded[0] & 0x80 != 0) return error.InvalidEncoding;

    var magnitude = encoded;
    if (encoded[0] == 0) {
        if (encoded.len > 1 and encoded[1] & 0x80 == 0) return error.InvalidEncoding;
        if (encoded.len > 1) magnitude = encoded[1..];
    }
    if (magnitude.len > destination.len) return error.InvalidEncoding;
    @memset(destination, 0);
    @memcpy(destination[destination.len - magnitude.len ..], magnitude);
}

test "canonical DER round trips and P-521 long length" {
    inline for (.{ 32, 48, 66 }) |scalar_len| {
        var raw: [scalar_len * 2]u8 = [_]u8{0} ** (scalar_len * 2);
        raw[0] = 0x80;
        raw[scalar_len] = 1;
        var der: [141]u8 = undefined;
        const len = try encode(&raw, scalar_len, &der);
        if (scalar_len == 66) try std.testing.expectEqual(@as(u8, 0x81), der[1]);
        var decoded: [scalar_len * 2]u8 = undefined;
        try decode(der[0..len], scalar_len, &decoded);
        try std.testing.expectEqualSlices(u8, &raw, &decoded);
    }
}

test "malformed DER is rejected without partial output" {
    const malformed = [_][]const u8{
        &.{},
        &.{ 0x30, 0x80, 0, 0 },
        &.{ 0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 1 },
        &.{ 0x30, 0x07, 0x02, 0x02, 0, 1, 0x02, 0x01, 1 },
        &.{ 0x30, 0x06, 0x02, 0x01, 1, 0x02, 0x01, 1, 0 },
        &.{ 0x30, 0x81, 0x06, 0x02, 0x01, 1, 0x02, 0x01, 1 },
    };
    for (malformed) |der| {
        var raw: [64]u8 = [_]u8{0xa5} ** 64;
        try std.testing.expectError(error.InvalidEncoding, decode(der, 32, &raw));
        try std.testing.expectEqualSlices(u8, &([_]u8{0xa5} ** 64), &raw);
    }

    var short_output = [_]u8{0xa5} ** 8;
    const raw = [_]u8{1} ** 64;
    try std.testing.expectError(error.InvalidLength, encode(&raw, 32, &short_output));
    try std.testing.expectEqualSlices(u8, &([_]u8{0xa5} ** 8), &short_output);
}
