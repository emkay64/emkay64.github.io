---
title:  Cleaning CRT and Win32 Dependencies From Your MSVC Compiled Binary
categories: Windows
classes: wide
---

Stripping Win32 and CRT dependencies from windows PEs to solely depend on NTDLL.dll. 


## Tooling
- Dependencies.exe lucasg - https://github.com/lucasg/Dependencies/releases/download/v1.11.1/Dependencies_x64_Release.zip
- Process hacker NT Headers - https://github.com/processhacker/phnt.git


## Setup dependencies / resources 
Add ntdll.lib dependency
```
Project Properties Page -> Configuration Properties -> Linker -> All Options -> Additional Dependencies -> (Add ntdll.lib)
```

Include PHNT Headers into header unit dependencies
```
Project Properties Page -> Configuration Properties -> C/C++ -> All Options -> Additonal Include Directories -> $(ProjectDir)phnt;%(AdditionalHeaderUnitDependencies) 
```

Define includes 
```c
#include "phnt_windows.h"
#include "phnt.h"
```

You can now call NTAPI functions  
```c
void main(void){
    DbgPrint("Ayylmao\n");
}
```

## Strip win32 & CRT 
```
Project Properties Page -> Configuration Properties -> Linker -> Ignore All Default Libraries -> Yes (/NODEFAULTLIB)
Project Properties Page -> Configuration Properties -> Linker -> Show Progress -> Display all progress messages (/VERBOSE)
Project Properties Page -> Configuration Properties -> Linker -> Entry Point -> "WhateverYouWant"
Project Properties Page -> Configuration Properties -> Linker -> Generate Debug Info -> Generate Debug Information optimized for sharing and publishing (/DEBUG:FULL)

Project Properties Page -> Configuration Properties -> C/C++ -> Basic Runtime Checks -> Default ((to avoid linking in __RTC_*. )
Project Properties Page -> Configuration Properties -> C/C++ -> Security Check = Disable Security Check (/GS-)
```
    
## Do that thang
```
Rebuild started...
1>------ Rebuild All started: Project: win32_crt_less, Configuration: Debug x64 ------
1>win32_crt_less.c
1>Processed /NODEFAULTLIB (suppressing all default libs)
1>Starting pass 1
1>Searching libraries
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\kernel32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\user32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\gdi32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\winspool.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\comdlg32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\advapi32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\shell32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\ole32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\oleaut32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\uuid.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\odbc32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\odbccp32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\ntdll.lib:
1>      Found __imp_DbgPrint
1>        Referenced in win32_crt_less.obj
1>        Loaded ntdll.lib(ntdll.dll)
1>      Found __IMPORT_DESCRIPTOR_ntdll
1>        Referenced in ntdll.lib(ntdll.dll)
1>        Loaded ntdll.lib(ntdll.dll)
1>      Found __NULL_IMPORT_DESCRIPTOR
1>        Referenced in ntdll.lib(ntdll.dll)
1>        Loaded ntdll.lib(ntdll.dll)
1>      Found ntdll_NULL_THUNK_DATA
1>        Referenced in ntdll.lib(ntdll.dll)
1>        Loaded ntdll.lib(ntdll.dll)
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\kernel32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\user32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\gdi32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\winspool.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\comdlg32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\advapi32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\shell32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\ole32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\oleaut32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\uuid.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\odbc32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\odbccp32.lib:
1>Finished searching libraries
1>Searching libraries
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\kernel32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\user32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\gdi32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\winspool.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\comdlg32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\advapi32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\shell32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\ole32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\oleaut32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\uuid.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\odbc32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\odbccp32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\ntdll.lib:
1>Finished searching libraries
1>Searching libraries
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\kernel32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\user32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\gdi32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\winspool.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\comdlg32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\advapi32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\shell32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\ole32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\oleaut32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\uuid.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\odbc32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\odbccp32.lib:
1>    Searching C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\ntdll.lib:
1>Finished searching libraries
1>Finished pass 1
1>Invoking rc.exe:
1> /v
1> /x
1> /fo
1> "C:\Users\p4\AppData\Local\Temp\lnk{86A8A118-0C90-45D9-AE8B-A7A4999D727D}.tmp"
1> "C:\Users\p4\AppData\Local\Temp\lnk{004AE08D-4C1A-4A2F-BBE7-901C9CA6578E}.tmp"
1>Microsoft (R) Windows (R) Resource Compiler Version 10.0.10011.16384
1>
1>Copyright (C) Microsoft Corporation.  All rights reserved.
1>
1>
1>Using codepage 1252 as default
1>Creating C:\Users\p4\AppData\Local\Temp\lnk{86A8A118-0C90-45D9-AE8B-A7A4999D727D}.tmp
1>
1>
1>C:\Users\p4\AppData\Local\Temp\lnk{004AE08D-4C1A-4A2F-BBE7-901C9CA6578E}.tmp.
1>Writing 24:1,	lang:0x409,	size 381
1>Invoking cvtres.exe:
1> /machine:amd64
1> /verbose
1> /out:"C:\Users\p4\AppData\Local\Temp\lnk{00AC8A1B-30C1-461D-81EC-8FC63D855BB7}.tmp"
1> /readonly
1> "C:\Users\p4\AppData\Local\Temp\lnk{86A8A118-0C90-45D9-AE8B-A7A4999D727D}.tmp"
1>Microsoft (R) Windows Resource To Object Converter Version 14.29.30145.0
1>Copyright (C) Microsoft Corporation.  All rights reserved.
1>
1>adding resource. type:MANIFEST, name:1, language:0x0409, flags:0x30, size:381
1>Unused libraries:
1>  C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\kernel32.lib
1>  C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\user32.lib
1>  C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\gdi32.lib
1>  C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\winspool.lib
1>  C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\comdlg32.lib
1>  C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\advapi32.lib
1>  C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\shell32.lib
1>  C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\ole32.lib
1>  C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\oleaut32.lib
1>  C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\uuid.lib
1>  C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\odbc32.lib
1>  C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0\um\x64\odbccp32.lib
1>Starting pass 2
1>     * linker generated manifest res *
1>     win32_crt_less.obj
1>     ntdll.lib(ntdll.dll)
1>     ntdll.lib(ntdll.dll)
1>     ntdll.lib(ntdll.dll)
1>     ntdll.lib(ntdll.dll)
1>Finished pass 2
1>win32_crt_less.vcxproj -> C:\Users\p4\source\repos\win32_crt_less\x64\Debug\win32_crt_less.exe
========== Rebuild All: 1 succeeded, 0 failed, 0 skipped ==========
```

## Dependencies output
```
Dependencies
File View Options Help
win32_crt_less
C:\Users\p4\source\repos\win32_crt_less\x64\Debug\win32_crt_less.exe
    C:\Windows\system32\ntdll.dll
PI    Ordinal Hint              Function Module                         Delayed
IC    N/A     34 (0x00000022)   DbgPrint C:\Windows\system32\ntdll.dll  False

VirtualAddress
Module                          Machine Type                File Size   Image Base  Virtual Size    Entry point Subsystem   Subsystem Ver.  Checksum
C:\Windows\system32\ntdll.dll   AMD64   Dll; Executable     0x001ef5b8  0x180000000 0x001f8000      0x00000000  0x00000003  10.0            0x001f3b49 (correct)
```