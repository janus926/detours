@echo off

start /b .\detours\bin.X86\syelogd.exe /q .\tracefrag.log

setlocal
set TRCMEM_SKIP_STACK_WITH_SYMBOL=chunk_alloc_mmap_slow,js::gc::MapAlignedPagesSlow
start /wait .\detours\bin.X86\withdll.exe /d:".\detours\bin.X86\trcmem32.dll" %*
endlocal

taskkill /f /im "syelogd.exe"
