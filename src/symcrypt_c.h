#if defined(_WIN32)
#undef _MSC_VER
#undef __GNUC__
#define __GNUC__ 4
#endif
#define SYMCRYPT_ZIG_IMPORT 1
#include <stddef.h>
#include <symcrypt.h>
#include <symcrypt_ec_encoding.h>
