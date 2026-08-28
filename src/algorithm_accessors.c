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

#define SYMCRYPT_ZIG_IMPORT_HASH_DATA(name) \
    __declspec(dllimport) extern const PCSYMCRYPT_HASH name

SYMCRYPT_ZIG_IMPORT_HASH_DATA(SymCryptMd5Algorithm);
SYMCRYPT_ZIG_IMPORT_HASH_DATA(SymCryptSha1Algorithm);
SYMCRYPT_ZIG_IMPORT_HASH_DATA(SymCryptSha256Algorithm);
SYMCRYPT_ZIG_IMPORT_HASH_DATA(SymCryptSha384Algorithm);
SYMCRYPT_ZIG_IMPORT_HASH_DATA(SymCryptSha512Algorithm);
SYMCRYPT_ZIG_IMPORT_HASH_DATA(SymCryptSha3_256Algorithm);
SYMCRYPT_ZIG_IMPORT_HASH_DATA(SymCryptSha3_384Algorithm);
SYMCRYPT_ZIG_IMPORT_HASH_DATA(SymCryptSha3_512Algorithm);

PCSYMCRYPT_HASH SymCryptZigMd5Algorithm(void) { return SymCryptMd5Algorithm; }
PCSYMCRYPT_HASH SymCryptZigSha1Algorithm(void) { return SymCryptSha1Algorithm; }
PCSYMCRYPT_HASH SymCryptZigSha256Algorithm(void) { return SymCryptSha256Algorithm; }
PCSYMCRYPT_HASH SymCryptZigSha384Algorithm(void) { return SymCryptSha384Algorithm; }
PCSYMCRYPT_HASH SymCryptZigSha512Algorithm(void) { return SymCryptSha512Algorithm; }
PCSYMCRYPT_HASH SymCryptZigSha3_256Algorithm(void) { return SymCryptSha3_256Algorithm; }
PCSYMCRYPT_HASH SymCryptZigSha3_384Algorithm(void) { return SymCryptSha3_384Algorithm; }
PCSYMCRYPT_HASH SymCryptZigSha3_512Algorithm(void) { return SymCryptSha3_512Algorithm; }

#define SYMCRYPT_ZIG_IMPORT_CURVE_DATA(name) \
    __declspec(dllimport) extern const PCSYMCRYPT_ECURVE_PARAMS name

SYMCRYPT_ZIG_IMPORT_CURVE_DATA(SymCryptEcurveParamsNistP256);
SYMCRYPT_ZIG_IMPORT_CURVE_DATA(SymCryptEcurveParamsNistP384);
SYMCRYPT_ZIG_IMPORT_CURVE_DATA(SymCryptEcurveParamsNistP521);
SYMCRYPT_ZIG_IMPORT_CURVE_DATA(SymCryptEcurveParamsCurve25519);

PCSYMCRYPT_ECURVE_PARAMS SymCryptZigEcurveParamsNistP256(void) { return SymCryptEcurveParamsNistP256; }
PCSYMCRYPT_ECURVE_PARAMS SymCryptZigEcurveParamsNistP384(void) { return SymCryptEcurveParamsNistP384; }
PCSYMCRYPT_ECURVE_PARAMS SymCryptZigEcurveParamsNistP521(void) { return SymCryptEcurveParamsNistP521; }
PCSYMCRYPT_ECURVE_PARAMS SymCryptZigEcurveParamsCurve25519(void) { return SymCryptEcurveParamsCurve25519; }
