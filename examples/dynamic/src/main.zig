const std = @import("std");
const symcrypt = @import("symcrypt");

pub fn main() !void {
    try symcrypt.init();
    const digest = try symcrypt.hash.digest(.sha256, "abc");
    const encoded = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(
        u8,
        &encoded,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )) return error.KnownAnswerMismatch;
}
