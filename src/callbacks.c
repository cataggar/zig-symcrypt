#if defined(_WIN32)
#include <malloc.h>
#else
#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#endif

#include <stddef.h>
#include <symcrypt.h>

PVOID SYMCRYPT_CALL SymCryptCallbackAlloc(SIZE_T nBytes)
{
    SIZE_T size = nBytes == 0 ? 1 : nBytes;
#if defined(_WIN32)
    return _aligned_malloc(size, SYMCRYPT_ASYM_ALIGN_VALUE);
#else
    void *p = NULL;
    if (posix_memalign(&p, SYMCRYPT_ASYM_ALIGN_VALUE, size) != 0) {
        return NULL;
    }
    return p;
#endif
}

VOID SYMCRYPT_CALL SymCryptCallbackFree(PVOID pMem)
{
#if defined(_WIN32)
    _aligned_free(pMem);
#else
    free(pMem);
#endif
}
