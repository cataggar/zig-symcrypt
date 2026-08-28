#if defined(_WIN32)
#define WIN32_NO_STATUS
#include <windows.h>
#include <windef.h>
#include <bcrypt.h>
#else
#include <stddef.h>
#endif

#include <symcrypt.h>

#if defined(_WIN32)
SYMCRYPT_ENVIRONMENT_WINDOWS_USERMODE_LATEST;
#else
SYMCRYPT_ENVIRONMENT_POSIX_USERMODE;
#endif
