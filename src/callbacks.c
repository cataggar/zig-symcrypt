#if defined(_WIN32)
#define WIN32_NO_STATUS
#include <windows.h>
#include <bcrypt.h>
#include <malloc.h>
#else
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/random.h>
#endif

#include <stddef.h>
#include <stdint.h>
#include <symcrypt.h>

static SIZE_T g_symcrypt_zig_fail_allocation = (SIZE_T)-1;
static SIZE_T g_symcrypt_zig_allocation_count = 0;

VOID SymCryptZigTestFailAllocationAfter(SIZE_T allocationIndex)
{
    g_symcrypt_zig_allocation_count = 0;
    g_symcrypt_zig_fail_allocation = allocationIndex;
}

VOID SymCryptZigTestDisableAllocationFailure(void)
{
    g_symcrypt_zig_allocation_count = 0;
    g_symcrypt_zig_fail_allocation = (SIZE_T)-1;
}

PVOID SYMCRYPT_CALL SymCryptCallbackAlloc(SIZE_T nBytes)
{
    SIZE_T allocationIndex = g_symcrypt_zig_allocation_count++;
    if (allocationIndex == g_symcrypt_zig_fail_allocation) {
        return NULL;
    }
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

SYMCRYPT_ERROR SYMCRYPT_CALL SymCryptCallbackRandom(PBYTE pbBuffer, SIZE_T cbBuffer)
{
#if defined(_WIN32)
    SIZE_T offset = 0;
    while (offset < cbBuffer) {
        SIZE_T remaining = cbBuffer - offset;
        ULONG chunk = remaining > UINT32_MAX ? UINT32_MAX : (ULONG)remaining;
        NTSTATUS status = BCryptGenRandom(NULL, pbBuffer + offset, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0) {
            return SYMCRYPT_EXTERNAL_FAILURE;
        }
        offset += chunk;
    }
#else
    SIZE_T offset = 0;
    while (offset < cbBuffer) {
        ssize_t result = getrandom(pbBuffer + offset, cbBuffer - offset, 0);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return SYMCRYPT_EXTERNAL_FAILURE;
        }
        if (result == 0) {
            return SYMCRYPT_EXTERNAL_FAILURE;
        }
        offset += (SIZE_T)result;
    }
#endif
    return SYMCRYPT_NO_ERROR;
}

PVOID SYMCRYPT_CALL SymCryptCallbackAllocateMutexFastInproc(void)
{
#if defined(_WIN32)
    CRITICAL_SECTION *mutex = (CRITICAL_SECTION *)malloc(sizeof(*mutex));
    if (mutex == NULL) {
        return NULL;
    }
    if (!InitializeCriticalSectionEx(mutex, 0, 0)) {
        free(mutex);
        return NULL;
    }
    return mutex;
#else
    pthread_mutex_t *mutex = (pthread_mutex_t *)malloc(sizeof(*mutex));
    if (mutex == NULL) {
        return NULL;
    }
    if (pthread_mutex_init(mutex, NULL) != 0) {
        free(mutex);
        return NULL;
    }
    return mutex;
#endif
}

VOID SYMCRYPT_CALL SymCryptCallbackFreeMutexFastInproc(PVOID pMutex)
{
    if (pMutex == NULL) {
        return;
    }
#if defined(_WIN32)
    DeleteCriticalSection((CRITICAL_SECTION *)pMutex);
#else
    (void)pthread_mutex_destroy((pthread_mutex_t *)pMutex);
#endif
    free(pMutex);
}

VOID SYMCRYPT_CALL SymCryptCallbackAcquireMutexFastInproc(PVOID pMutex)
{
#if defined(_WIN32)
    EnterCriticalSection((CRITICAL_SECTION *)pMutex);
#else
    (void)pthread_mutex_lock((pthread_mutex_t *)pMutex);
#endif
}

VOID SYMCRYPT_CALL SymCryptCallbackReleaseMutexFastInproc(PVOID pMutex)
{
#if defined(_WIN32)
    LeaveCriticalSection((CRITICAL_SECTION *)pMutex);
#else
    (void)pthread_mutex_unlock((pthread_mutex_t *)pMutex);
#endif
}
