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
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <symcrypt.h>

static atomic_flag g_symcrypt_zig_allocation_lock = ATOMIC_FLAG_INIT;
static _Atomic bool g_symcrypt_zig_fail_enabled = false;
static _Atomic bool g_symcrypt_zig_defer_failure = false;
static _Atomic bool g_symcrypt_zig_deferred_failure_hit = false;
static _Atomic SIZE_T g_symcrypt_zig_fail_allocation = (SIZE_T)-1;
static _Atomic SIZE_T g_symcrypt_zig_allocation_count = 0;
static _Atomic SIZE_T g_symcrypt_zig_successful_allocations = 0;
static _Atomic SIZE_T g_symcrypt_zig_freed_allocations = 0;

static void SymCryptZigAllocationLock(void)
{
    while (atomic_flag_test_and_set_explicit(
        &g_symcrypt_zig_allocation_lock,
        memory_order_acquire))
    {
    }
}

static void SymCryptZigAllocationUnlock(void)
{
    atomic_flag_clear_explicit(&g_symcrypt_zig_allocation_lock, memory_order_release);
}

VOID SymCryptZigTestFailAllocationAfter(SIZE_T allocationIndex)
{
    SymCryptZigAllocationLock();
    atomic_store_explicit(&g_symcrypt_zig_allocation_count, 0, memory_order_relaxed);
    atomic_store_explicit(&g_symcrypt_zig_successful_allocations, 0, memory_order_relaxed);
    atomic_store_explicit(&g_symcrypt_zig_freed_allocations, 0, memory_order_relaxed);
    atomic_store_explicit(&g_symcrypt_zig_fail_allocation, allocationIndex, memory_order_relaxed);
    atomic_store_explicit(&g_symcrypt_zig_defer_failure, false, memory_order_relaxed);
    atomic_store_explicit(&g_symcrypt_zig_deferred_failure_hit, false, memory_order_relaxed);
    atomic_store_explicit(&g_symcrypt_zig_fail_enabled, true, memory_order_release);
    SymCryptZigAllocationUnlock();
}

VOID SymCryptZigTestDeferAllocationFailureAfter(SIZE_T allocationIndex)
{
    SymCryptZigAllocationLock();
    atomic_store_explicit(&g_symcrypt_zig_allocation_count, 0, memory_order_relaxed);
    atomic_store_explicit(&g_symcrypt_zig_successful_allocations, 0, memory_order_relaxed);
    atomic_store_explicit(&g_symcrypt_zig_freed_allocations, 0, memory_order_relaxed);
    atomic_store_explicit(&g_symcrypt_zig_fail_allocation, allocationIndex, memory_order_relaxed);
    atomic_store_explicit(&g_symcrypt_zig_defer_failure, true, memory_order_relaxed);
    atomic_store_explicit(&g_symcrypt_zig_deferred_failure_hit, false, memory_order_relaxed);
    atomic_store_explicit(&g_symcrypt_zig_fail_enabled, true, memory_order_release);
    SymCryptZigAllocationUnlock();
}

VOID SymCryptZigTestDisableAllocationFailure(void)
{
    SymCryptZigAllocationLock();
    atomic_store_explicit(&g_symcrypt_zig_fail_enabled, false, memory_order_release);
    atomic_store_explicit(&g_symcrypt_zig_defer_failure, false, memory_order_relaxed);
    atomic_store_explicit(&g_symcrypt_zig_deferred_failure_hit, false, memory_order_relaxed);
    atomic_store_explicit(&g_symcrypt_zig_fail_allocation, (SIZE_T)-1, memory_order_relaxed);
    atomic_store_explicit(&g_symcrypt_zig_allocation_count, 0, memory_order_relaxed);
    atomic_store_explicit(&g_symcrypt_zig_successful_allocations, 0, memory_order_relaxed);
    atomic_store_explicit(&g_symcrypt_zig_freed_allocations, 0, memory_order_relaxed);
    SymCryptZigAllocationUnlock();
}

BOOLEAN SymCryptZigTestConsumeDeferredAllocationFailure(void)
{
    if (!atomic_load_explicit(&g_symcrypt_zig_fail_enabled, memory_order_acquire) ||
        !atomic_load_explicit(&g_symcrypt_zig_defer_failure, memory_order_relaxed))
    {
        return FALSE;
    }
    SymCryptZigAllocationLock();
    BOOLEAN result =
        atomic_load_explicit(&g_symcrypt_zig_fail_enabled, memory_order_relaxed) &&
        atomic_load_explicit(&g_symcrypt_zig_defer_failure, memory_order_relaxed) &&
        atomic_exchange_explicit(
        &g_symcrypt_zig_deferred_failure_hit,
        false,
        memory_order_relaxed) ? TRUE : FALSE;
    SymCryptZigAllocationUnlock();
    return result;
}

SIZE_T SymCryptZigTestOutstandingAllocations(void)
{
    SymCryptZigAllocationLock();
    SIZE_T allocations = atomic_load_explicit(
        &g_symcrypt_zig_successful_allocations,
        memory_order_relaxed);
    SIZE_T frees = atomic_load_explicit(
        &g_symcrypt_zig_freed_allocations,
        memory_order_relaxed);
    SymCryptZigAllocationUnlock();
    return allocations >= frees ? allocations - frees : (SIZE_T)-1;
}

PVOID SYMCRYPT_CALL SymCryptCallbackAlloc(SIZE_T nBytes)
{
    SIZE_T size = nBytes == 0 ? 1 : nBytes;
    bool testEnabled = atomic_load_explicit(
        &g_symcrypt_zig_fail_enabled,
        memory_order_acquire);
    if (testEnabled)
    {
        SymCryptZigAllocationLock();
        testEnabled = atomic_load_explicit(
            &g_symcrypt_zig_fail_enabled,
            memory_order_acquire);
        if (!testEnabled)
        {
            SymCryptZigAllocationUnlock();
        }
        else
        {
            SIZE_T allocationIndex = atomic_fetch_add_explicit(
                &g_symcrypt_zig_allocation_count,
                1,
                memory_order_relaxed);
            SIZE_T failureIndex = atomic_load_explicit(
                &g_symcrypt_zig_fail_allocation,
                memory_order_relaxed);
            if (allocationIndex == failureIndex)
            {
                if (atomic_load_explicit(
                    &g_symcrypt_zig_defer_failure,
                    memory_order_relaxed))
                {
                    atomic_store_explicit(
                        &g_symcrypt_zig_deferred_failure_hit,
                        true,
                        memory_order_release);
                }
                else
                {
                    SymCryptZigAllocationUnlock();
                    return NULL;
                }
            }
        }
    }

    PVOID result;
#if defined(_WIN32)
    result = _aligned_malloc(size, SYMCRYPT_ASYM_ALIGN_VALUE);
#else
    void *p = NULL;
    if (posix_memalign(&p, SYMCRYPT_ASYM_ALIGN_VALUE, size) != 0) {
        result = NULL;
    } else {
        result = p;
    }
#endif
    if (testEnabled)
    {
        if (result != NULL)
        {
            atomic_fetch_add_explicit(
                &g_symcrypt_zig_successful_allocations,
                1,
                memory_order_release);
        }
        SymCryptZigAllocationUnlock();
    }
    return result;
}

VOID SYMCRYPT_CALL SymCryptCallbackFree(PVOID pMem)
{
    if (pMem != NULL && atomic_load_explicit(
        &g_symcrypt_zig_fail_enabled,
        memory_order_acquire))
    {
        SymCryptZigAllocationLock();
        if (atomic_load_explicit(
            &g_symcrypt_zig_fail_enabled,
            memory_order_acquire))
        {
            atomic_fetch_add_explicit(
                &g_symcrypt_zig_freed_allocations,
                1,
                memory_order_release);
        }
        SymCryptZigAllocationUnlock();
    }
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
