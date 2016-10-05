//////////////////////////////////////////////////////////////////////////////
//
//  Detours Test Program (trcmem.cpp of trcmem.dll)
//
//  Microsoft Research Detours Package, Version 3.0.
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
#define _WIN32_WINNT        0x0400
#define WIN32
#define NT

#define DBG_TRACE           0

#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include <map>
#include "detours.h"
#include "syelog.h"

#define PULONG_PTR          PVOID
#define PLONG_PTR           PVOID
#define ULONG_PTR           PVOID
#define ENUMRESNAMEPROCA    PVOID
#define ENUMRESNAMEPROCW    PVOID
#define ENUMRESLANGPROCA    PVOID
#define ENUMRESLANGPROCW    PVOID
#define ENUMRESTYPEPROCA    PVOID
#define ENUMRESTYPEPROCW    PVOID
#define STGOPTIONS          PVOID

#define STACK_DEPTH         64

//////////////////////////////////////////////////////////////////////////////

#pragma warning(disable:4127)   // Many of our asserts are constants.

#define ASSERT_ALWAYS(x)   \
    do {                                                        \
    if (!(x)) {                                                 \
            AssertMessage(#x, __FILE__, __LINE__);              \
            DebugBreak();                                       \
    }                                                           \
    } while (0)

#ifndef NDEBUG
#define ASSERT(x)           ASSERT_ALWAYS(x)
#else
#define ASSERT(x)
#endif

#define UNUSED(c)    (c) = (c)

//////////////////////////////////////////////////////////////////////////////
static HMODULE s_hInst = NULL;
static CHAR s_szDllPath[MAX_PATH];

VOID _PrintEnter(const CHAR *psz, ...);
VOID _PrintExit(const CHAR *psz, ...);
VOID _Print(const CHAR *psz, ...);
VOID _VPrint(PCSTR msg, va_list args, PCHAR pszBuf, LONG cbBuf);

VOID AssertMessage(CONST PCHAR pszMsg, CONST PCHAR pszFile, ULONG nLine);

//////////////////////////////////////////////////////////////////////////////
// Trampolines
//
extern "C" {

    HANDLE (WINAPI *
            Real_CreateFileW)(LPCWSTR a0,
                              DWORD a1,
                              DWORD a2,
                              LPSECURITY_ATTRIBUTES a3,
                              DWORD a4,
                              DWORD a5,
                              HANDLE a6)
        = CreateFileW;

    BOOL (WINAPI *
          Real_WriteFile)(HANDLE hFile,
                          LPCVOID lpBuffer,
                          DWORD nNumberOfBytesToWrite,
                          LPDWORD lpNumberOfBytesWritten,
                          LPOVERLAPPED lpOverlapped)
        = WriteFile;
    BOOL (WINAPI *
          Real_FlushFileBuffers)(HANDLE hFile)
        = FlushFileBuffers;
    BOOL (WINAPI *
          Real_CloseHandle)(HANDLE hObject)
        = CloseHandle;

    BOOL (WINAPI *
          Real_WaitNamedPipeW)(LPCWSTR lpNamedPipeName, DWORD nTimeOut)
        = WaitNamedPipeW;
    BOOL (WINAPI *
          Real_SetNamedPipeHandleState)(HANDLE hNamedPipe,
                                        LPDWORD lpMode,
                                        LPDWORD lpMaxCollectionCount,
                                        LPDWORD lpCollectDataTimeout)
        = SetNamedPipeHandleState;

    DWORD (WINAPI *
           Real_GetCurrentProcessId)(VOID)
        = GetCurrentProcessId;
    VOID (WINAPI *
          Real_GetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime)
        = GetSystemTimeAsFileTime;

    VOID (WINAPI *
          Real_InitializeCriticalSection)(LPCRITICAL_SECTION lpSection)
        = InitializeCriticalSection;
    VOID (WINAPI *
          Real_EnterCriticalSection)(LPCRITICAL_SECTION lpSection)
        = EnterCriticalSection;
    VOID (WINAPI *
          Real_LeaveCriticalSection)(LPCRITICAL_SECTION lpSection)
        = LeaveCriticalSection;
}

#if _MSC_VER < 1300
LPVOID (WINAPI *
        Real_HeapAlloc)(HANDLE hHeap, DWORD dwFlags, DWORD dwBytes)
    = HeapAlloc;
#else
LPVOID (WINAPI *
        Real_HeapAlloc)(HANDLE hHeap, DWORD dwFlags, DWORD_PTR dwBytes)
    = HeapAlloc;
#endif

DWORD (WINAPI * Real_GetModuleFileNameW)(HMODULE a0,
                                         LPWSTR a1,
                                         DWORD a2)
    = GetModuleFileNameW;

DWORD (WINAPI * Real_GetModuleFileNameA)(HMODULE a0,
                                         LPSTR a1,
                                         DWORD a2)
    = GetModuleFileNameA;

BOOL (WINAPI * Real_CreateProcessW)(LPCWSTR a0,
                                    LPWSTR a1,
                                    LPSECURITY_ATTRIBUTES a2,
                                    LPSECURITY_ATTRIBUTES a3,
                                    BOOL a4,
                                    DWORD a5,
                                    LPVOID a6,
                                    LPCWSTR a7,
                                    struct _STARTUPINFOW* a8,
                                    LPPROCESS_INFORMATION a9)
    = CreateProcessW;

NTSTATUS (__stdcall * Real_NtAllocateVirtualMemory)(HANDLE a0,
                                                    PVOID* a1,
                                                    ULONG_PTR a2,
                                                    PSIZE_T a3,
                                                    ULONG a4,
                                                    ULONG a5)
    = NULL;

NTSTATUS (__stdcall * Real_NtFreeVirtualMemory)(HANDLE a0,
                                                PVOID* a1,
                                                PSIZE_T a2,
                                                ULONG a3)
    = NULL;

USHORT (WINAPI * CaptureStackBackTrace)(ULONG,
                                        ULONG,
                                        PVOID*,
                                        PULONG)
    = NULL;

BOOL (WINAPI * Real_CreateProcessAsUserW)(HANDLE a0,
                                          LPCWSTR a1,
                                          LPWSTR a2,
                                          LPSECURITY_ATTRIBUTES a3,
                                          LPSECURITY_ATTRIBUTES a4,
                                          BOOL a5,
                                          DWORD a6,
                                          LPVOID a7,
                                          LPCWSTR a8,
                                          LPSTARTUPINFOW a9,
                                          LPPROCESS_INFORMATION a10)
    = CreateProcessAsUserW;

//////////////////////////////////////////////////////////////////////////////
// Detours
//
#if _MSC_VER < 1300
LPVOID WINAPI Mine_HeapAlloc(HANDLE hHeap, DWORD dwFlags, DWORD dwBytes)
#else
LPVOID WINAPI Mine_HeapAlloc(HANDLE hHeap, DWORD dwFlags, DWORD_PTR dwBytes)
#endif
{
    _PrintEnter("HeapAlloc(%p, %x, %p))\n", hHeap, dwFlags, dwBytes);

    LPVOID rv = 0;
    __try {
        rv = Real_HeapAlloc(hHeap, dwFlags, dwBytes);
    } __finally {
        _PrintExit("HeapAlloc() -> %p\n", rv);
    };
    return rv;
}

BOOL WINAPI Mine_CreateProcessW(LPCWSTR lpApplicationName,
                                LPWSTR lpCommandLine,
                                LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                BOOL bInheritHandles,
                                DWORD dwCreationFlags,
                                LPVOID lpEnvironment,
                                LPCWSTR lpCurrentDirectory,
                                LPSTARTUPINFOW lpStartupInfo,
                                LPPROCESS_INFORMATION lpProcessInformation)
{
    _PrintEnter("CreateProcessW(%ls,%ls,%p,%p,%x,%x,%p,%ls,%p,%p)\n",
                lpApplicationName,
                lpCommandLine,
                lpProcessAttributes,
                lpThreadAttributes,
                bInheritHandles,
                dwCreationFlags,
                lpEnvironment,
                lpCurrentDirectory,
                lpStartupInfo,
                lpProcessInformation);

    _Print("Calling DetourCreateProcessWithDllExW(,%hs)\n", s_szDllPath);

    BOOL rv = 0;
    __try {
        rv = DetourCreateProcessWithDllExW(lpApplicationName,
                                           lpCommandLine,
                                           lpProcessAttributes,
                                           lpThreadAttributes,
                                           bInheritHandles,
                                           dwCreationFlags,
                                           lpEnvironment,
                                           lpCurrentDirectory,
                                           lpStartupInfo,
                                           lpProcessInformation,
                                           s_szDllPath,
                                           Real_CreateProcessW);
    } __finally {
        _PrintExit("CreateProcessW(,,,,,,,,,) -> %x\n", rv);
    };
    return rv;
}

static HANDLE s_hMyHeap;

template<class T>
struct MyHeapAllocator
{
    typedef T value_type;
    MyHeapAllocator() { if (!s_hMyHeap) s_hMyHeap = HeapCreate(0, 0, 0); }
    ~MyHeapAllocator() { if (s_hMyHeap) HeapDestroy(s_hMyHeap); }
    template<class U> MyHeapAllocator(const MyHeapAllocator<U>& other) {}
    template<class U> bool operator==(const MyHeapAllocator<U>&) { return true; }
    template<class U> bool operator!=(const MyHeapAllocator<U>&) { return false; }
    T* allocate(size_t n) {
        return static_cast<T*>(HeapAlloc(s_hMyHeap, 0, n * sizeof(T)));
    }
    void deallocate(T* p, size_t n) {
        HeapFree(s_hMyHeap, 0, p);
    }
};

typedef struct
{
    PVOID addr;
    SIZE_T size;
    ULONG type;
    ULONG protect;
} Allocation;

typedef std::map<ULONG, PVOID*, std::less<ULONG>, MyHeapAllocator<std::pair<ULONG, PVOID*>>> StackMap;
typedef std::multimap<ULONG, Allocation*, std::less<ULONG>, MyHeapAllocator<std::pair<ULONG, Allocation*>>> AllocMap;

static StackMap s_stacks;
static AllocMap s_allocs;
static LONG s_nTlsNestAlloc;

NTSTATUS __stdcall Mine_NtAllocateVirtualMemory(HANDLE ProcessHandle,
                                                PVOID *BaseAddress,
                                                ULONG_PTR ZeroBits,
                                                PSIZE_T RegionSize,
                                                ULONG AllocationType,
                                                ULONG Protect)
{
    _PrintEnter("NtAllocateVirtualMemory(%p,%p,%x,%Iu,%x,%x)\n",
                ProcessHandle,
                *BaseAddress,
                ZeroBits,
                *RegionSize,
                AllocationType,
                Protect);

    NTSTATUS rv = 0;
    __try {
        rv = Real_NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
                                          RegionSize, AllocationType, Protect);

        // We care only the case when the size is not 64k-aligned and the type
        // is MEM_RESERVE or MEM_RESERVE | MEM_COMMIT.
        // TODO: configurable fitler for the type and protect flag.
        if (rv >= 0 && PtrToUlong(*RegionSize) & 0xffff &&
            AllocationType & MEM_RESERVE && !TlsGetValue(s_nTlsNestAlloc)) {
            TlsSetValue(s_nTlsNestAlloc, (LPVOID)1);

            ULONG hash;
            PVOID* bt = (PVOID*)HeapAlloc(s_hMyHeap, HEAP_ZERO_MEMORY,
                                          sizeof(PVOID) * STACK_DEPTH);
            (CaptureStackBackTrace)(1, STACK_DEPTH, bt, &hash);
            if (s_stacks.find(hash) != s_stacks.end()) {
                HeapFree(s_hMyHeap, 0, bt);
            } else {
                s_stacks.insert(std::pair<ULONG, PVOID*>(hash, bt));
            }

            Allocation* alloc = (Allocation*)HeapAlloc(s_hMyHeap, HEAP_ZERO_MEMORY,
                                                       sizeof(Allocation));
            alloc->addr = *BaseAddress;
            alloc->size = *RegionSize;
            alloc->type = AllocationType;
            alloc->protect = Protect;
            s_allocs.insert(std::pair<ULONG, Allocation*>(hash, alloc));

            TlsSetValue(s_nTlsNestAlloc, (LPVOID)0);
        }
    } __finally {
        _PrintExit("NtAllocateVirtualMemory(,,,,,) -> %x %p\n", rv, *BaseAddress);
    };
    return rv;
}

NTSTATUS __stdcall Mine_NtFreeVirtualMemory(HANDLE ProcessHandle,
                                            PVOID *BaseAddress,
                                            PSIZE_T RegionSize,
                                            ULONG FreeType)
{
    _PrintEnter("NtFreeVirtualMemory(%p,%p,%Iu,%x)\n",
                ProcessHandle,
                BaseAddress,
                RegionSize,
                FreeType);

    NTSTATUS rv = 0;
    __try {
        rv = Real_NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize,
                                      FreeType);
    } __finally {
        _PrintExit("NtFreeVirtualMemory(,,,) -> %x\n", rv);
    }
    return rv;
}

BOOL WINAPI Mine_CreateProcessAsUserW(HANDLE hToken,
                                      LPCWSTR lpApplicationName,
                                      LPWSTR lpCommandLine,
                                      LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                      LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                      BOOL bInheritHandles,
                                      DWORD dwCreationFlags,
                                      LPVOID lpEnvironment,
                                      LPCWSTR lpCurrentDirectory,
                                      LPSTARTUPINFOW lpStartupInfo,
                                      LPPROCESS_INFORMATION lpProcessInformation)
{
    _PrintEnter("CreateProcessAsUserW(%p,%ls,%ls,%p,%p,%x,%x,%p,%ls,%p,%p)\n",
                hToken,
                lpApplicationName,
                lpCommandLine,
                lpProcessAttributes,
                lpThreadAttributes,
                bInheritHandles,
                dwCreationFlags,
                lpEnvironment,
                lpCurrentDirectory,
                lpStartupInfo,
                lpProcessInformation);

    BOOL rv;
    __try {
        // TODO: Maybe DetourCreateProcessWithDllExW?
        rv = Real_CreateProcessAsUserW(hToken,
                                       lpApplicationName,
                                       lpCommandLine,
                                       lpProcessAttributes,
                                       lpThreadAttributes,
                                       bInheritHandles,
                                       dwCreationFlags,
                                       lpEnvironment,
                                       lpCurrentDirectory,
                                       lpStartupInfo,
                                       lpProcessInformation);
    } __finally {
        _PrintExit("CreateProcessAsUser(,,,,,,,,,,) -> %x\n", rv);
    }
    return rv;
}

//////////////////////////////////////////////////////////////////////////////
// AttachDetours
//
PCHAR DetRealName(PCHAR psz)
{
    PCHAR pszBeg = psz;
    // Move to end of name.
    while (*psz) {
        psz++;
    }
    // Move back through A-Za-z0-9 names.
    while (psz > pszBeg &&
           ((psz[-1] >= 'A' && psz[-1] <= 'Z') ||
            (psz[-1] >= 'a' && psz[-1] <= 'z') ||
            (psz[-1] >= '0' && psz[-1] <= '9'))) {
        psz--;
    }
    return psz;
}

VOID DetAttach(PVOID *ppbReal, PVOID pbMine, PCHAR psz)
{
    LONG l = DetourAttach(ppbReal, pbMine);
    if (l != 0) {
        Syelog(SYELOG_SEVERITY_NOTICE,
               "Attach failed: `%s': error %d\n", DetRealName(psz), l);
    }
}

VOID DetDetach(PVOID *ppbReal, PVOID pbMine, PCHAR psz)
{
    LONG l = DetourDetach(ppbReal, pbMine);
    if (l != 0) {
        Syelog(SYELOG_SEVERITY_NOTICE,
               "Detach failed: `%s': error %d\n", DetRealName(psz), l);
    }
}

#define ATTACH(x)       DetAttach(&(PVOID&)Real_##x,Mine_##x,#x)
#define DETACH(x)       DetDetach(&(PVOID&)Real_##x,Mine_##x,#x)

LONG AttachDetours(VOID)
{
    Real_NtAllocateVirtualMemory =
        ((NTSTATUS (__stdcall *)(HANDLE,
                                 PVOID*,
                                 ULONG_PTR,
                                 PSIZE_T,
                                 ULONG,
                                 ULONG))
        DetourFindFunction("ntdll.dll", "NtAllocateVirtualMemory"));

    Real_NtFreeVirtualMemory =
        ((NTSTATUS (__stdcall *)(HANDLE,
                                 PVOID*,
                                 PSIZE_T,
                                 ULONG))
        DetourFindFunction("ntdll.dll", "NtFreeVirtualMemory"));

    CaptureStackBackTrace =
        ((USHORT (WINAPI *)(ULONG,
                            ULONG,
                            PVOID*,
                            PULONG))
        DetourFindFunction("kernel32.dll", "RtlCaptureStackBackTrace"));

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    ATTACH(CreateProcessW);
    ATTACH(CreateProcessAsUserW);
    ATTACH(HeapAlloc);
    ATTACH(NtAllocateVirtualMemory);
    ATTACH(NtFreeVirtualMemory);

    return DetourTransactionCommit();
}

LONG DetachDetours(VOID)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DETACH(CreateProcessAsUserW);
    DETACH(CreateProcessW);
    DETACH(HeapAlloc);
    DETACH(NtAllocateVirtualMemory);
    DETACH(NtFreeVirtualMemory);

    return DetourTransactionCommit();
}

////////////////////////////////////////////////////////////// Logging System.
//
static BOOL s_bLog = FALSE;
static LONG s_nTlsIndent = -1;
static LONG s_nTlsThread = -1;
static LONG s_nThreadCnt = 0;
static CHAR s_szBuf[1024];

VOID _PrintEnter(const CHAR *psz, ...)
{
    DWORD dwErr = GetLastError();

    LONG nIndent = 0;
    LONG nThread = 0;
    if (s_nTlsIndent >= 0) {
        nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent);
        TlsSetValue(s_nTlsIndent, (PVOID)(LONG_PTR)(nIndent + 1));
    }
    if (s_nTlsThread >= 0) {
        nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
    }

    if (s_bLog && psz) {
        PCHAR pszBuf = s_szBuf;
        PCHAR pszEnd = s_szBuf + ARRAYSIZE(s_szBuf) - 1;
        LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;
        *pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
        *pszBuf++ = ' ';
        while (nLen-- > 0) {
            *pszBuf++ = ' ';
        }

        va_list  args;
        va_start(args, psz);

        while ((*pszBuf++ = *psz++) != 0 && pszBuf < pszEnd) {
            // Copy characters.
        }
        *pszEnd = '\0';
        SyelogV(SYELOG_SEVERITY_INFORMATION, s_szBuf, args);

        va_end(args);
    }
    SetLastError(dwErr);
}

VOID _PrintExit(const CHAR *psz, ...)
{
    DWORD dwErr = GetLastError();

    LONG nIndent = 0;
    LONG nThread = 0;
    if (s_nTlsIndent >= 0) {
        nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent) - 1;
        ASSERT(nIndent >= 0);
        TlsSetValue(s_nTlsIndent, (PVOID)(LONG_PTR)nIndent);
    }
    if (s_nTlsThread >= 0) {
        nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
    }

    if (s_bLog && psz) {
        PCHAR pszBuf = s_szBuf;
        PCHAR pszEnd = s_szBuf + ARRAYSIZE(s_szBuf) - 1;
        LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;
        *pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
        *pszBuf++ = ' ';
        while (nLen-- > 0) {
            *pszBuf++ = ' ';
        }

        va_list  args;
        va_start(args, psz);

        while ((*pszBuf++ = *psz++) != 0 && pszBuf < pszEnd) {
            // Copy characters.
        }
        *pszEnd = '\0';
        SyelogV(SYELOG_SEVERITY_INFORMATION,
                s_szBuf, args);

        va_end(args);
    }
    SetLastError(dwErr);
}

VOID _Print(const CHAR *psz, ...)
{
    DWORD dwErr = GetLastError();

    LONG nIndent = 0;
    LONG nThread = 0;
    if (s_nTlsIndent >= 0) {
        nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent);
    }
    if (s_nTlsThread >= 0) {
        nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
    }

    if (s_bLog && psz) {
        PCHAR pszBuf = s_szBuf;
        PCHAR pszEnd = s_szBuf + ARRAYSIZE(s_szBuf) - 1;
        LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;
        *pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
        *pszBuf++ = ' ';
        while (nLen-- > 0) {
            *pszBuf++ = ' ';
        }

        va_list  args;
        va_start(args, psz);

        while ((*pszBuf++ = *psz++) != 0 && pszBuf < pszEnd) {
            // Copy characters.
        }
        *pszEnd = '\0';
        SyelogV(SYELOG_SEVERITY_INFORMATION,
                s_szBuf, args);

        va_end(args);
    }

    SetLastError(dwErr);
}

VOID AssertMessage(CONST PCHAR pszMsg, CONST PCHAR pszFile, ULONG nLine)
{
    Syelog(SYELOG_SEVERITY_FATAL,
           "ASSERT(%s) failed in %s, line %d.\n", pszMsg, pszFile, nLine);
}

//////////////////////////////////////////////////////////////////////////////
//
// DLL module information
//
BOOL ThreadAttach(HMODULE hDll)
{
    (void)hDll;

    if (s_nTlsIndent >= 0) {
        TlsSetValue(s_nTlsIndent, (PVOID)0);
    }
    if (s_nTlsThread >= 0) {
        LONG nThread = InterlockedIncrement(&s_nThreadCnt);
        TlsSetValue(s_nTlsThread, (PVOID)(LONG_PTR)nThread);
    }
    return TRUE;
}

BOOL ThreadDetach(HMODULE hDll)
{
    (void)hDll;

    if (s_nTlsIndent >= 0) {
        TlsSetValue(s_nTlsIndent, (PVOID)0);
    }
    if (s_nTlsThread >= 0) {
        TlsSetValue(s_nTlsThread, (PVOID)0);
    }
    return TRUE;
}

BOOL ProcessAttach(HMODULE hDll)
{
    s_bLog = FALSE;
    s_nTlsIndent = TlsAlloc();
    s_nTlsThread = TlsAlloc();
    s_nTlsNestAlloc = TlsAlloc();

    WCHAR wzExePath[MAX_PATH];

    s_hInst = hDll;
    Real_GetModuleFileNameA(s_hInst, s_szDllPath, ARRAYSIZE(s_szDllPath));
    Real_GetModuleFileNameW(NULL, wzExePath, ARRAYSIZE(wzExePath));

    SyelogOpen("trcmem" DETOURS_STRINGIFY(DETOURS_BITS), SYELOG_FACILITY_APPLICATION);
    Syelog(SYELOG_SEVERITY_INFORMATION, "##########################################\n");
    Syelog(SYELOG_SEVERITY_INFORMATION, "### %ls\n", wzExePath);

    LONG error = AttachDetours();
    if (error != NO_ERROR) {
        Syelog(SYELOG_SEVERITY_FATAL, "### Error attaching detours: %d\n", error);
    }

    ThreadAttach(hDll);

    s_bLog = TRUE;
    return TRUE;
}

VOID DumpTraces(VOID)
{
    static CHAR s_symbuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    HANDLE hProcess = GetCurrentProcess();
    CRITICAL_SECTION lock;

    InitializeCriticalSection(&lock);
    EnterCriticalSection(&lock);

    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    // TODO: get sympath from command line or env
    if (!SymInitialize(hProcess, "C:\\w\\fx\\mc\\obj-i686-pc-mingw32\\dist\\bin;"
            "SRV*c:\\symcache\\*http://msdl.microsoft.com/download/symbols", TRUE)) {
        DWORD error = GetLastError();
        Syelog(SYELOG_SEVERITY_FATAL, "### Error initializing the symbol handler"
               ": %d\n", error);
    }

    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)s_symbuf;
    DWORD64 dwDisplacement = 0;
    IMAGEHLP_MODULE64 module;

    memset(&module, 0, sizeof(module));
    module.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    memset(s_symbuf, 0, sizeof(s_symbuf));
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    // TODO: apply filter
    for (StackMap::iterator it = s_stacks.begin(); it != s_stacks.end(); ++it) {
        INT i;
        PVOID* stack = it->second;
        Syelog(SYELOG_SEVERITY_INFORMATION, "0x%x %p\n", it->first, it->second);

        /* Output the stack symbols. */
        for (i = 0; i < STACK_DEPTH && stack[i]; ++i) {
            SymGetModuleInfo64(hProcess, (DWORD64)stack[i], &module);
            SymFromAddr(hProcess, (DWORD64)stack[i], &dwDisplacement, pSymbol);

            Syelog(SYELOG_SEVERITY_INFORMATION, "  [%d] %p %s!%s+0x%x\n", i,
                   stack[i], module.ModuleName, pSymbol->Name, dwDisplacement);

            memset(&module, 0, sizeof(module));
            module.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
            memset(s_symbuf, 0, sizeof(s_symbuf));
            pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
            pSymbol->MaxNameLen = MAX_SYM_NAME;
        }
        HeapFree(s_hMyHeap, 0, stack);

        /* List s_allocs from the current stack. */
        std::pair <AllocMap::iterator, AllocMap::iterator> allocs =
            s_allocs.equal_range(it->first);
        i = 0;
        for (AllocMap::iterator it = allocs.first; it != allocs.second; ++it) {
            Syelog(SYELOG_SEVERITY_INFORMATION, "  #%d %p %lu %x %x\n", ++i,
                   it->second->addr, it->second->size, it->second->type,
                   it->second->protect);
        }
    }

    if (!SymCleanup(hProcess)) {
        DWORD error = GetLastError();
        Syelog(SYELOG_SEVERITY_FATAL, "### Error terminating the symbol handler"
               ": %d\n", error);
    }

    LeaveCriticalSection(&lock);
    DeleteCriticalSection(&lock);
}

BOOL ProcessDetach(HMODULE hDll)
{
    ThreadDetach(hDll);
    s_bLog = FALSE;

    LONG error = DetachDetours();
    if (error != NO_ERROR) {
        Syelog(SYELOG_SEVERITY_FATAL, "### Error detaching detours: %d\n", error);
    }

    DumpTraces();

    Syelog(SYELOG_SEVERITY_NOTICE, "### Closing.\n");
    SyelogClose(FALSE);

    if (s_nTlsIndent >= 0) {
        TlsFree(s_nTlsIndent);
    }
    if (s_nTlsThread >= 0) {
        TlsFree(s_nTlsThread);
    }
    if (s_nTlsNestAlloc >= 0) {
        TlsFree(s_nTlsNestAlloc);
    }
    return TRUE;
}

BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD dwReason, PVOID lpReserved)
{
    (void)hModule;
    (void)lpReserved;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (dwReason) {
      case DLL_PROCESS_ATTACH:
        DetourRestoreAfterWith();
        return ProcessAttach(hModule);
      case DLL_PROCESS_DETACH:
        return ProcessDetach(hModule);
      case DLL_THREAD_ATTACH:
        return ThreadAttach(hModule);
      case DLL_THREAD_DETACH:
        return ThreadDetach(hModule);
    }
    return TRUE;
}
//
///////////////////////////////////////////////////////////////// End of File.
