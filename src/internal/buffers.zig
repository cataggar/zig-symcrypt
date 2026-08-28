const std = @import("std");
const errors = @import("../errors.zig");

pub fn checkedAdd(a: usize, b: usize) errors.Error!usize {
    return std.math.add(usize, a, b) catch error.ValueTooLarge;
}

pub fn overlaps(a: []const u8, b: []const u8) bool {
    if (a.len == 0 or b.len == 0) return false;
    const a_start = @intFromPtr(a.ptr);
    const b_start = @intFromPtr(b.ptr);
    const a_end = std.math.add(usize, a_start, a.len) catch return true;
    const b_end = std.math.add(usize, b_start, b.len) catch return true;
    return a_start < b_end and b_start < a_end;
}

pub fn requireDisjoint(a: []const u8, b: []const u8) errors.Error!void {
    if (overlaps(a, b)) return error.OverlappingBuffers;
}

pub fn requireDisjointFromAll(output: []const u8, inputs: anytype) errors.Error!void {
    inline for (inputs) |input| try requireDisjoint(output, input);
}

pub fn optionalConstPtr(bytes: []const u8) [*c]const u8 {
    return if (bytes.len == 0) null else @ptrCast(bytes.ptr);
}

pub fn constPtr(bytes: []const u8) [*c]const u8 {
    return @ptrCast(bytes.ptr);
}

pub fn mutPtr(bytes: []u8) [*c]u8 {
    return @ptrCast(bytes.ptr);
}

test "overlap checks are exact and overflow safe" {
    var bytes: [32]u8 = undefined;
    try std.testing.expect(overlaps(bytes[0..16], bytes[15..31]));
    try std.testing.expect(overlaps(bytes[15..31], bytes[0..16]));
    try std.testing.expect(overlaps(bytes[4..12], bytes[0..16]));
    try std.testing.expect(!overlaps(bytes[0..16], bytes[16..32]));
    try std.testing.expect(!overlaps(bytes[0..0], bytes[0..16]));
}
