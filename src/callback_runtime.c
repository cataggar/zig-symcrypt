#if defined(_WIN32)
#define WIN32_NO_STATUS
#include <windows.h>
#include <bcrypt.h>
#else
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/random.h>
#endif

#include <stdint.h>
#include <stdlib.h>
#include <symcrypt.h>

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
