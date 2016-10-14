# What Is This
A tool that use [Detours](https://www.microsoft.com/en-us/research/project/detours/) to intercept NtAllocateVirtualMemory and track 64k-unaligned virtual memory allocation from a 32-bit program. This was created for diagnosing virutal address space fragmentation of 32-bit Firefox ([bug 1299747](https://bugzilla.mozilla.org/show_bug.cgi?id=1299747)), but I expect it can also be useful for other programs.
# Prerequisites
### Visual C++
Download [Visual Studio Community](https://www.visualstudio.com/downloads/#d-community) and install Visual C++. Be sure to have C++ Common Tool installed.
### Debug Help Library (dbghelp.dll)
Go to http://go.microsoft.com/fwlink/p/?linkid=84137 and download Debugging Tools for Windows.
### Disable Frame-Pointer Omission (/Oy-)
Make sure the binary you're going to intercept is built with FPO disabled to have meaningful stack, see https://msdn.microsoft.com/en-us/library/2kxx5t2c.aspx.

# Build
```
C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat
cd detours; nmake
```

# Run
```
tracefrag.bat <cmd>
```
e.g.,
```
tracefrag.bat C:\mc\obj-i686-pc-mingw32\dist\bin\firefox.exe --no-remote
```
Note to have symbols translated correctly, you may need to specify the symbol path in environment variable _NT_SYMBOL_PATH or _NT_ALTERNATE_SYMBOL_PATH.

# Output
### Sample
```
20161014051312272 7140 50.60: trcmem32: 0x90ccc973 e50a60
20161014051312272 7140 50.60: trcmem32:   [0] 7447D5DE KERNELBASE!VirtualAllocExNuma+0x3e
20161014051312272 7140 50.60: trcmem32:   [1] 7447D58B KERNELBASE!VirtualAllocEx+0x1b
20161014051312272 7140 50.60: trcmem32:   [2] 6AEC5361 xul!mozilla::internal::WindowsDllDetourPatcher::Init+0x4c
20161014051312273 7140 50.60: trcmem32:   [3] 6AEC2314 xul!mozilla::WindowsDllInterceptor::AddDetour+0x2b
20161014051312273 7140 50.60: trcmem32:   [4] 6B181AE8 xul!`anonymous namespace'::InitCreateWindowHook+0x33
20161014051312273 7140 50.60: trcmem32:   [5] 00AC168C plugin-container!content_process_main+0xc2
20161014051312273 7140 50.60: trcmem32:   [6] 00AC18E7 plugin-container!wmain+0x121
20161014051312273 7140 50.60: trcmem32:   [7] 00ACEE99 plugin-container!__scrt_common_main_seh+0xf9
20161014051312273 7140 50.60: trcmem32:   [8] 770562C4 KERNEL32!BaseThreadInitThunk+0x24
20161014051312273 7140 50.60: trcmem32:   [9] 77210609 ntdll!RtlSubscribeWnfStateChangeNotification+0x439
20161014051312273 7140 50.60: trcmem32:   [10] 772105D4 ntdll!RtlSubscribeWnfStateChangeNotification+0x404
20161014051312273 7140 50.60: trcmem32:   #1 e00000 4096 3000 40 4865890 0
```
### Fields
```
20161014051312272 7140 50.60: trcmem32: 0x90ccc973 e50a60
^^^^^^^^^^^^^^^^^ ^^^^                  ^^^^^^^^^^
a                 b                     c
```
a = timestamp  
b = pid  
c = hash of the stack backtrace


```
20161014051312273 7140 50.60: trcmem32:   #1 e00000 4096 3000 40 4865890 0
                                          ^^ ^^^^^^ ^^^^ ^^^^ ^^ ^^^^^^^ ^
                                          a  b      c    d    e  f       g
```
a = serial number of allocation  
b = address (hex)  
c = size  
d = allocation type (hex)  
e = memory protection (hex)  
f = tick of allocation  
g = tick of deallocatation, 0 means hasn't deallocated
