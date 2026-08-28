#if defined(_MSC_VER)
#undef _MSC_VER
#define __GNUC__ 4
#endif

#include <symcrypt.h>

#if !defined(_WIN32)
#error This import-data shim is only needed for dynamic Windows builds.
#endif

#define SYMCRYPT_ZIG_IMPORT_DATA(name) \
    __declspec(dllimport) extern const PCSYMCRYPT_MAC name

#define SYMCRYPT_ZIG_IMPORT_BLOCKCIPHER(name) \
    __declspec(dllimport) extern const PCSYMCRYPT_BLOCKCIPHER name

SYMCRYPT_ZIG_IMPORT_DATA(SymCryptHmacMd5Algorithm);
SYMCRYPT_ZIG_IMPORT_DATA(SymCryptHmacSha1Algorithm);
SYMCRYPT_ZIG_IMPORT_DATA(SymCryptHmacSha256Algorithm);
SYMCRYPT_ZIG_IMPORT_DATA(SymCryptHmacSha384Algorithm);
SYMCRYPT_ZIG_IMPORT_DATA(SymCryptHmacSha512Algorithm);
SYMCRYPT_ZIG_IMPORT_DATA(SymCryptHmacSha3_224Algorithm);
SYMCRYPT_ZIG_IMPORT_DATA(SymCryptHmacSha3_256Algorithm);
SYMCRYPT_ZIG_IMPORT_DATA(SymCryptHmacSha3_384Algorithm);
SYMCRYPT_ZIG_IMPORT_DATA(SymCryptHmacSha3_512Algorithm);
SYMCRYPT_ZIG_IMPORT_BLOCKCIPHER(SymCryptAesBlockCipher);

PCSYMCRYPT_MAC SymCryptZigHmacMd5Algorithm(void) { return SymCryptHmacMd5Algorithm; }
PCSYMCRYPT_MAC SymCryptZigHmacSha1Algorithm(void) { return SymCryptHmacSha1Algorithm; }
PCSYMCRYPT_MAC SymCryptZigHmacSha256Algorithm(void) { return SymCryptHmacSha256Algorithm; }
PCSYMCRYPT_MAC SymCryptZigHmacSha384Algorithm(void) { return SymCryptHmacSha384Algorithm; }
PCSYMCRYPT_MAC SymCryptZigHmacSha512Algorithm(void) { return SymCryptHmacSha512Algorithm; }
PCSYMCRYPT_MAC SymCryptZigHmacSha3_224Algorithm(void) { return SymCryptHmacSha3_224Algorithm; }
PCSYMCRYPT_MAC SymCryptZigHmacSha3_256Algorithm(void) { return SymCryptHmacSha3_256Algorithm; }
PCSYMCRYPT_MAC SymCryptZigHmacSha3_384Algorithm(void) { return SymCryptHmacSha3_384Algorithm; }
PCSYMCRYPT_MAC SymCryptZigHmacSha3_512Algorithm(void) { return SymCryptHmacSha3_512Algorithm; }
PCSYMCRYPT_BLOCKCIPHER SymCryptZigAesBlockCipher(void) { return SymCryptAesBlockCipher; }
