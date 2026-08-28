const builtin = @import("builtin");
const std = @import("std");
const options = @import("symcrypt_options");
const c = @import("../c.zig").raw;

extern fn SymCryptZigAesBlockCipher() c.PCSYMCRYPT_BLOCKCIPHER;

pub fn aesBlockCipher() c.PCSYMCRYPT_BLOCKCIPHER {
    return if (comptime builtin.target.os.tag == .windows and
        std.mem.eql(u8, options.linkage, "dynamic"))
        SymCryptZigAesBlockCipher()
    else
        c.SymCryptAesBlockCipher;
}
