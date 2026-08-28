const std = @import("std");
const symcrypt = @import("symcrypt");

test {
    _ = @import("native.zig");
    std.testing.refAllDecls(symcrypt);
    std.testing.refAllDecls(symcrypt.hash);
    std.testing.refAllDecls(symcrypt.hmac);
    std.testing.refAllDecls(symcrypt.hkdf);
    std.testing.refAllDecls(symcrypt.aead);
    std.testing.refAllDecls(symcrypt.cipher);
    std.testing.refAllDecls(symcrypt.asymmetric);
    std.testing.refAllDecls(symcrypt.asymmetric.ecdsa_der);
    std.testing.refAllDecls(symcrypt.asymmetric.ecc);
    std.testing.refAllDecls(symcrypt.asymmetric.x25519);
    std.testing.refAllDecls(symcrypt.asymmetric.rsa);
}
