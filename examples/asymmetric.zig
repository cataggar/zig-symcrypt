const std = @import("std");
const symcrypt = @import("symcrypt");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const private = try symcrypt.asymmetric.ecc.PrivateKey.generate(
        allocator,
        .p256,
        .signing_and_agreement,
    );
    defer private.deinit();
    const public = try private.publicKey(allocator);
    defer public.deinit();

    const digest = try symcrypt.hash.digest(.sha256, "message");
    var signature: [141]u8 = undefined;
    const signature_len = try private.sign(.sha256, &digest, &signature);
    try public.verify(.sha256, &digest, signature[0..signature_len]);
}
