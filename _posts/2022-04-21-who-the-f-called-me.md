---
title:  "Who the F Called Me?: Trampoline Hook Caller Function Metadata Acquisition"
categories: Windows
classes: wide
---

This was research that was done for a University BSc Cyber Security and Digital Forensics dissertation, this project was chosen as a challenge as my Windows OS knowledge at the time was weak. Didn't know more than how to write a hello world in c. Its very crudely copy pasted from my paper and with the knowledge obtained since could be improved on. Its interesting to see how things change with time. 


## Scenario
Win32 & CRT-less binary intended to early load by e.g. ELAM/KMDF driver using KAPC injection to force load. inspired by Dennis Babkin(InjectAll), wbenny(InjDrv/DetoursNT), ccob(Building And Breaking an edr) and the blogs read along the way.


## RIP/return address & __ReturnAddress() intrinsic
To obtain the target address to search for, the MSVC compiler intrinsic __ReturnAddress() can be used within each hooking function. Take the example below, the entry function calls the returnval function which utilizes this intrinsic and prints the address which a RET instruction will return to. In this case pointing back within the main function, The instruction after the function call to be specific. This logic will be valuable in a later section.

{% highlight c %}
#include <stdio.h>
#include <intrin.h>
#pragma intrinsic(_ReturnAddress)

void returnval(void)
{
	/* the value printed will be within the main function */
	printf("Return Address: 0x%p\n", (void*)_ReturnAddress()); 
}

void main(void)
{
	returnval(); /* the function call */
	/* <- here is where the program will logically return to after executing the function returnval() */
}
{% endhighlight %}


## Hooking Win32 from a NTAPI dependant dll?
Hooking the Win32 API and the NTAPI with Microsoft Detours is trivial. Hooking Win32 from DetoursNT was not as easy. To use DetoursNT as a hooking library in our situation to hook Win32 functions, a pointer to the entry point of the function to be hooked is needed to be obtained in order to apply the detour. 

This can be carried out in a similar way to the LoadLibrary + GetProcAddress method used to resolve functions dynamically which can be utilized from Win32 to obtain function pointers; however this needs to use Win32.

The method that was discovered was using the Ldr functions exported by NTDLL.DLL to copy the functionality of LoadLibrary + GetProcAddress. LdrLoadDll and LdrGetProcedureAddress were utilized with the function prototypes provided by process hackers NT headers.

{% highlight c %}
RtlInitUnicodeString(&ModuleNameString_U, L"kernelbase");
Status = LdrLoadDll(UNICODE_NULL, NULL, &ModuleNameString_U, &ModuleHandle);

RtlInitString(&ProcedureNameString, "VirtualAlloc");
Status = LdrGetProcedureAddress(ModuleHandle, &ProcedureNameString, (ULONG)NULL, (PVOID*)&ProcedurePointer);

void* VirtualAllocPointer = ProcedurePointer;

/* 
fnVirtualAlloc is just a custom function prototype typedef which can be applied to the pointer to 
setup according to calling conv
*/
typedef LPVOID(NTAPI * fnVirtualAlloc)(
	/* [in, optional]*/ LPVOID lpAddress,
	/* [in]          */ SIZE_T dwSize,
	/* [in]          */ DWORD  flAllocationType,
	/* [in]          */ DWORD  flProtect
);
	
OrigVirtualAlloc = (fnVirtualAlloc)VirtualAllocPointer;
{% endhighlight %}

This could be used as follows:
{% highlight c %}
#define WIN32_LEAN_AND_MEAN
#include <cstdio>
#include <Windows.h>

void main(void) {
	printf("%-20s : 0x%-016p\n", "Original:", (void*)VirtualAlloc);
	HMODULE SampleHookDllModule = LoadLibrary(TEXT("SampleHookDLL.dll"));
	printf("%-20s : 0x%-016p\n", "Hook:", (void*)VirtualAlloc);
	void* exec_mem = VirtualAlloc(0, 69, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	FreeLibrary(SampleHookDllModule);
	printf("%-20s : 0x%-016p\n\nDONE\n", "Unhook:", (void*)VirtualAlloc);
}
{% endhighlight %}


## What module called
Now that Win32 and NTAPI functions can be hooked, the calling module can be isolated via a pointer within loaded image ranges. Information about the context of the hook will be useful for providing greater insight into what image and function is actually calling what. The PEB is a valuable structure when it comes to finding information about process execution however can be tampered with due to living in user mode (Chappell 2022) but in this proof of concept this will not be taken into account.

The PEB can be programmatically accessed using the readgsqword MSVC compiler intrinsic (Microsoft 2022a) with 0x60 (96 bytes) as the offset to read the PEB for x86-64 bit processes.

{% highlight c %}
/* PEB structure */
typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[21];
	PPEB_LDR_DATA LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	BYTE Reserved3[520];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved4[136];
	ULONG SessionId;
} PEB;


/* _PEB_LDR_DATA Member of the PEB structure */
typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

/* 
* NOTE: If you dont know what a LIST_ENTRY structure is , learn it, its everywhere in windows 
* and is very easy to understand 
*/
typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;						/* THIS IS WHAT WE WANT */
	PVOID EntryPoint;					/* THIS IS WHAT WE WANT */
	PVOID Reserved3;
	UNICODE_STRING FullDllName;			/* THIS IS WHAT WE WANT */
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
{% endhighlight %}

{% highlight c %}
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

void main(void)
{
	/*
	LDR_DATA_TABLE_ENTRY_COMPLETED struct goes here
	*/
	PPEB pPEB = (PPEB)__readgsqword(0x60);
	PEB_LDR_DATA* peb_ldr_data = pPEB->Ldr;
	LIST_ENTRY* list_head = &(peb_ldr_data->InMemoryOrderModuleList);
	LIST_ENTRY* list_entry;
	LDR_DATA_TABLE_ENTRY_COMPLETED* ldr_entry;
	for (list_entry = list_head->Flink; list_entry != list_head; list_entry = list_entry->Flink) 
	{
		ldr_entry = (LDR_DATA_TABLE_ENTRY_COMPLETED*)((char*)list_entry - sizeof(LIST_ENTRY));
		
		printf("DLL Name %ws\n", 
		ldr_entry->BaseDllName.Buffer);
		
		printf("Base Address 0x%p\n", 
		(void *)ldr_entry->DllBase);
		
		printf("SizeOfImage 0x%p\n", 
		(void *)ldr_entry->SizeOfImage);
		
		printf("End Address 0x%p\n\n", 
		(void*)((ULONGLONG)ldr_entry->DllBase+(ULONGLONG)ldr_entry->SizeOfImage));
	}
}
{% endhighlight %}


## What function called
The plaintext function name will not be in a Release version of a compiled PE with no debug symbols unless exported as so. Exports are references to functions within the DLL which are stored in an export table for use by external processes that load the DLL (wireless90 2021). A feature of the Windows 64-bit ABI (Microsoft 2021o) is that Exception handler records will be registered for functions which allocate stack space or call another function within, called non-leaf functions. Both KERNELBASE.DLL and NTDLL.DLL have a .pdata section of the PE32+ which is populated by a table of sorted RUNTIME FUNCTION (Microsoft 2021j) structures and this provides information valuable for isolating function specific details (Microsoft 2021p).

The BeginAddress from the RUNTIME FUNCTION structure is the target function entry address. This will be used as the target function in the next stage to search the EXPORT DIRECTORY of the PE.

{% highlight c %}
typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
	DWORD BeginAddress; /* Interested in this */
	DWORD EndAddress;
	union {
		DWORD UnwindInfoAddress;
		DWORD UnwindData;
	} DUMMYUNIONNAME;
} _IMAGE_RUNTIME_FUNCTION_ENTRY, *_PIMAGE_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;
{% endhighlight %}

To obtain a RUNTIME FUNCTION function for a chosen RIP, the NTDLL.DLL exported function RtlLookupFunctionEntry() can be used.
{% highlight c %}
EXTERN_C NTSYSAPI PRUNTIME_FUNCTION NTAPI RtlLookupFunctionEntry(
/* [in] */ DWORD64 ControlPc,
/* [out] */ PDWORD64 ImageBase,
/* [out] */ PUNWIND_HISTORY_TABLE HistoryTable
);
[...SNIP...]
runfunc = RtlLookupFunctionEntry(ullRetAddr, &imgbase, &HistTable);
{% endhighlight %}

Now the function BeginAddress can be used to search the PE for an Exported function name. The PE structure features a Directory called the EXPORT DIRECTORY (wireless90 2021) which contains information about the exported functions. For example, CFF Explorer (NTCore 2018) can be used to view the PE structure in depth. The Export directory is the first entry in the Data Directory section at index [0]. Holding an ordinal if set, the function RVA, the name Ordinal, the Name RVA and the Name.

The function name can be obtained by iterating over the entries in the Export Directory until the address matches. This is carried out via standard PE parsing using the Known and publicly documented PE file structure and structures available. It’s questionable whether creating a sorted vector of these structures to save having to parse the PE headers each time, however this is room for future experimentation. The snippet below is a cut down hybrid of a couple of scripts, sektor7 and arbiter34.
{% highlight c %}
[...SNIP...]
if ((PIMAGE_DOS_HEADER)imgbase)->e_magic == IMAGE_DOS_SIGNATURE)
{
[...SNIP...]
	if ((IMAGE_NT_HEADERS*)(imgbase)+pIDH->e_lfanew))->Signature == IMAGE_NT_SIGNATURE)
	{
[...SNIP...]
		if (pDD->Size != 0 && pDD->VirtualAddress != 0) // check if the export directory VA / SIZE is not 0
			printf("Have Export directory for module\n");
			[...SNIP...]
		for (i = 0; i < ExportDir->NumberOfNames; i++)
		{
			char * sTmpFuncName = (char *) pBaseAddr + (DWORD_PTR) pFuncNameTbl[i];
			[...SNIP...]
			if (addToSearch == imgbase + [pHintsTbl[i]]))
			{
				[...SNIP...]
				printf("name : %s\n", sTmpFuncName);
			}
		[...SNIP...]
		}
	}
[...SNIP...]
}
[...SNIP...]
{% endhighlight %}

NOTE: One limitation of this approach is the function to be searched for needs to be exported by the DLL being searched and if it’s not it’s likely a private function or pointing back into the host executable.


## Putting the pieces together
The complete functionality of a Call to a hooked function can be described below. After The DLL has been injected into malproc64.exe and Hooks have been applied.

```
1. VirtualAlloc gets called by malproc64.exe
	(a) Hook function HookVirtualAlloc gets hit
	(b) ReturnAddress() within the hook function is compared to each PE’s in InMemoryOrderModuleList from the PEB,
	if from malproc64.exe:
		HOOKHIT:WIN32:HookVirtualAlloc, (caller module:NOT OG:malproc64.exe:UnknownFunction),
	else:
		continue
	
2. VirtualAlloc Call within KERNELBASE.DLL triggers Hook on NtAllocateVirtualMemory
	(a) Hook function HookNtAllocateVirtualMemory gets hit
	(b) ReturnAddress() within the hook function is compared to each PE in InMemoryOrderModuleList from the PEB,
	if from malproc64.exe:
		HOOKHIT:WIN32:HookVirtualAlloc, (caller module:malproc64.exe),
	else:
		(c) ReturnAddress() value 0x00007FF62F1C11A2 is passed to RtlLookupFunctionEntry which returns a 
		PRUNTIME FUNCTION for the caller
		(d) PRUNTIME FUNCTION.BeginAddress used to parse PE and get function name of calling BeginAddress as it 
		will equal baseaddress + VirtualAlloc RVA of the function
		(e) HOOKHIT:NTAPI:HookNtAllocateVirtualMemory, 
			(caller module:KERNELBASE.dll:VirtualAlloc),
			(func:0x00007FFBF4D718E8)
```


To discuss and dissect results the sample source below, malproc64.c, calls VirtualAlloc, VirtualAllocEx, VirtualAllocExNuma, RtlMoveMemory, VirtualProtect, CreateThread. All the Win32 API’s and NTAPI counterparts in use are hooked apart from RtlMoveMemory. The DLL is force-loaded via LoadLibrary to simulate the injection at process creation.

{% highlight c %}
#include <Windows.h>
#include <stdio.h>
//#pragma comment(lib, "kernel32.lib") /* uncomment to catch kernel32.dll:CreateThread() */

#if _DEBUG
	#define DLL_PATH L"Z:\\sEDRDLL_V0.1\\Bin\\x64\\Debug\\SampleHookDLL.dll"
#else
	#define DLL_PATH L"Z:\\sEDRDLL_V0.1\\Bin\\x64\\Release\\SampleHookDLL.dll"
#endif

void main(void)
{
	DWORD oldprotect = 0;
	unsigned char payload[] = {0x90,0x90,0x90,0x90,0x90,0x90,0xc3,0xcc}; 		// 6xnop sled, int3, ret
	unsigned int payload_len = 10;
	HMODULE SampleHookDllModule = LoadLibrary(DLL_PATH);
	HANDLE cp = GetCurrentProcess();
	printf("Hit Enter To Start!!!");
	getchar();
	void * exec_mem = NULL;
	void * exec_mem2 = NULL;
	void * exec_mem3 = NULL;
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
	exec_mem2 = VirtualAllocEx(cp, NULL, 69, MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
	exec_mem3 = VirtualAllocExNuma(cp, NULL, 69, MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE, NULL);
	printf("%p\n%p\n%p\n", (void*)exec_mem, (void*)exec_mem2 , (void*)exec_mem3);
	RtlMoveMemory(exec_mem, payload, payload_len);
	BOOL rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
	HANDLE th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
	WaitForSingleObject(th, -1);
}
{% endhighlight %}


The log file created contains a line for each hook hit in the format of:

```
(DEBUGMESSAGE),\\
(APITYPE),\\
(HOOKFUNCNAME),\\
(HOOKDLL\_YN:CALLERMODULE:CALLINGFUNCTION),\\
(COUNT(Will be Depreciated)), \\
(RETADDRESS)
```

Each api call trace is split into groups of loglines with descriptions in the form of inline c comments.

```
/** Normal VirtualAlloc call (VirtualAlloc->[Zw/Nt]AllocateVirtualMemory) **/
/* UnknownCaller calls VirtualAlloc which hits HookVirtualAlloc */
HOOKHIT: WIN32:HookVirtualAlloc,(caller module: NOT_OG:malproc6464d.exe:UnknownCaller),
(count : 1),(func : 0x00007FF6CC4920E8)
/* HookNtAllocateVirtualMemory gets called by KERNELBASE.dll:VirtualAlloc */
HOOKHIT: NTAPI:HookNtAllocateVirtualMemory,(caller module: NOT_OG:KERNELBASE.dll:VirtualAlloc),
(count : 1),(func : 0x00007FFF650218E8)

/** Normal VirtualAllocEx call (VirtualAllocEx->VirtualAllocExNuma->[Zw/Nt]AllocateVirtualMemory) **/
/* UnknownCaller calls HookVirtualAllocEx which hits HookVirtualAllocExNuma */
HOOKHIT: WIN32:HookVirtualAllocEx,(caller module: NOT_OG:malproc6464d.exe:UnknownCaller),
(count : 1),(func : 0x00007FF6CC49210F)
/* HookVirtualAllocExNuma gets called by KERNELBASE.dll:VirtualAllocEx */
HOOKHIT: WIN32:HookVirtualAllocExNuma,(caller module: NOT_OG:KERNELBASE.dll:VirtualAllocEx),
(count : 1),(func : 0x00007FFF650351E6)
/* HookNtAllocateVirtualMemory gets called by KERNELBASE.dll:VirtualAllocExNuma */
HOOKHIT: NTAPI:HookNtAllocateVirtualMemory,(caller module: NOT_OG:KERNELBASE.dll:VirtualAllocExNuma),
(count : 1),(func : 0x00007FFF6503524D)

/** Normal HookVirtualAllocExNuma call (VirtualAllocExNuma->[Zw/Nt]AllocateVirtualMemory) **/
/* UnknownCaller calls HookVirtualAllocExNuma which hits HookNtAllocateVirtualMemory */
HOOKHIT: WIN32:HookVirtualAllocExNuma,(caller module: NOT_OG:malproc6464d.exe:UnknownCaller),
(count : 1),(func : 0x00007FF6CC49213E)
/* HookNtAllocateVirtualMemory gets called by KERNELBASE.dll:VirtualAllocExNuma */
HOOKHIT: NTAPI:HookNtAllocateVirtualMemory,(caller module: NOT_OG:KERNELBASE.dll:VirtualAllocExNuma),
(count : 1),(func : 0x00007FFF6503524D)

```
Its not nice on the eyes and was the source for some confusion, but thats the learning process. Make mistakes while experiementing and researching -> learn from it -> apply in the real world



## Bypassing detection

{% highlight assembly %}
; NOTE , WINDOWS 10 21H1 SYSCALL STUBS TAKEN FROM IDA DISASSEMBLY OF NTDLL.DLL
; FUNCTIONS ARE FORCE MADE PUBLIC IN THE MASM COMPILER OPTIONS

_DATA SEGMENT
_DATA ENDS
_TEXT SEGMENT

AlloeVirtMem PROC
	mov r10, rcx
	mov eax, 18h ; SYSCALL number for NtAllocateVirtualMemory
	syscall
	ret
AlloeVirtMem ENDP

WriVirMem PROC
	mov r10, rcx
	mov eax, 3Ah ; SYSCALL number for NtWriteVirtualMemory
	syscall
	ret
WriVirMem ENDP

ProtVirtMem PROC
	mov r10, rcx
	mov eax, 50h ; SYSCALL number for NtProtectVirtualMemory
	syscall
	ret
ProtVirtMem ENDP

CreThreE PROC
	mov r10, rcx
	mov eax, 0C1h ; SYSCALL number for NtCreateThreadEx
	syscall
	ret
CreThreE ENDP
_TEXT ENDS
END
{% endhighlight %}


{% highlight c %}
#include "syscall.h"
void ThisIsNotAnEntryPoint(void)
{
	DbgPrint("Custom Entrypoint ThisIsNotAnEntryPoint NOPSLED DEMO\n");
	// msfvenom calc.exe thread based shellcode
	unsigned char pload[] = {0xfc,0x48,0x83,0xe4/*[...SNIP...]*/,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00 };
	size_t pload_size = sizeof(pload);
	
	HANDLE ph = NtCurrentProcess();
	void * ba = NULL;
	NTSTATUS SysAllocateReturn = AlloeVirtMem(ph, &ba, 0, &pload_size, MEM_COMMIT |MEM_RESERVE, PAGE_READWRITE);
	DbgPrint("SysAllocateReturn\t%x\n", SysAllocateReturn);
	
	my_memmove(ba, (void*)pload, 276);
	DbgPrint("ba 0x%p", ba);
	
	ULONG nprt = PAGE_EXECUTE_READ;
	ULONG oprt = 0;
	NTSTATUS SysNtProtectReturn = ProtVirtMem(ph, &ba, &pload_size, nprt, &oprt);
	DbgPrint("SysNtProtectReturn\t%x\n", SysNtProtectReturn);
	
	HANDLE th = NULL;
	NTSTATUS SysNtCreateReturn = CreThreE(&th, GENERIC_EXECUTE, NULL, ph, ba, NULL,FALSE, 0, 0, 0, NULL);
	DbgPrint("SysNtCreateReturn\t%x\n", SysNtCreateReturn);
	
	DbgPrint("END");
	//WaitForSingleObject(th, -1); 	// to actually wait infinitely we need to link with kernel32, 
									// or be bothered to use ntapi equiv
}
{% endhighlight %}

As this PE is not importing functions from ntdll which will be hooked by the introspection DLL within the process, the PE using these syscall stubs will go unnoticed however a log file for the process will be created.

A breakpoint is put on the final call to CreateProcessInternalW in order to facilitate stepping through each stage of the introspection during execution shows the processes that go on behind the scenes.
	1. Introspection DLL gets force loaded into the process
	2. The DLL PROCESS ATTACH reason for call is passed to the DLL
	3. The log file based on PID and executable name is created.
	4. A range of Win32 hooks are applied successfully
	5. The syscall64d.exe binary carries out it’s thread based shellcode execution
	6. The breakpoint set on CreateProcessInternalW which is called by the msfvenom shellcode is hit


## Critical Review
At the beginning of the project the researcher had the aim of developing a Kernel Driver which can inject a custom DLL into processes and act as a provider and protector from malicious API usage patterns. This was inspired by an interest in how enterprise endpoint detection implement their user mode detection capabilities.

After 30 hours of KMDF driver programming based off of Dennis Babkin’s InjectAll blog (Babkin D. 2021b) and youtube series (Babkin D. 2021a), the researcher decided to shift focus from the driver to the DLL due to the complexity and number of tasks that would need to be completed in order to achieve the original aim in it’s entirety.

After developing the core proof of concepts the researcher came to the conclusion that developing detection capabilities further than access protection detection and buffer scanning was not feasible for this project’s time constraints put into place. With the weighting towards

By the end of the project the DLL was successfully developed alongside a range of tools and demo pieces, this allowed the researcher to dive deep and learn a good deal of Windows internals fundamentals.


## Revisions
The c code that was written is not safe by any means, warning messages and memory safety were not taken into account during the lifecycle of programming due to inexperience. A couple of rounds of Refactoring and code review will enable the application to be safer and made more efficient in terms of operation and codebase size. Using Nt NTAPI functions for file creation and management was difficult due to the lack of official documentation and inexperience but it was made to work through attaching a debugger and trial and error. 

{% highlight c %}
[...SNIP...]
/* CreateLogFile function which grabs PID and exe name and creates a log file in the
format
EXECUTABLE.EXE_PID.txt
For example: malproc64.exe_820.txt
*/
void CreateLogFile(void)
{
	/*[...SNIP...]*/
	/* setup object attributes */
	UNICODE_STRING uniName = { 0 };
	OBJECT_ATTRIBUTES objAttr;
	/* init unicode string in uniName */
	RtlInitUnicodeString(
		&uniName,
		outfile /* this filename was created earlier in function */
	);
	/* init object attributes to be returned for next call to open file */
	InitializeObjectAttributes(
		&objAttr, &uniName,
		0x00000040L, //OBJ_CASE_INSENSITIVE,
		NULL,NULL
	);
	NTSTATUS NtCreateFileStatus;
	HANDLE LogFileHandle;

#define FILE_OVERWRITE_IF 0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020

/* NtCreateFile call to NTDLL.DLL */
	NtCreateFileStatus = NtCreateFile(
		&LogFileHandle,
		FILE_GENERIC_WRITE, // | FILE_APPEND_DATA,
		&objAttr, &ioStatusBlock, NULL,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE,
		FILE_OVERWRITE_IF,FILE_SYNCHRONOUS_IO_NONALERT,NULL, 0
	);

	/*[...SNIP...]*/
	/* close handle so that other write operations are possible */
	NtClose(LogFileHandle);
}
{% endhighlight %}

To open a file and append a line to said file was not an easy task using NTAPI functions, once again it was a case of attaching a debugger and stepping through until NTSTATUS values returned 0x00000000.
{% highlight c %}
/*[...SNIP...]*/
/* AppendLogFile function which takes a pointer to an array of chars and a length of
chars to read from char array
Uses global filename to obtains a file handle using NtCreateFile
Appending the passed log line into the file using NtWriteFile */
void AppendLogFile(char TextToWrite[], int LenTextToWrite)
{
	/*[...SNIP...]*/
	UNICODE_STRING filename;
	RtlInitUnicodeString(&filename, outfile);
	/* initialize OBJECT_ATTRIBUTES */
	OBJECT_ATTRIBUTES objAtt;
	InitializeObjectAttributes(
		&objAtt, &filename,
		OBJ_CASE_INSENSITIVE, NULL, NULL
	);
	NTSTATUS NtCreateFileStatus;
	HANDLE FileHand;
	IO_STATUS_BLOCK ioSB;
	/* Handle to the created log file can be obtained */
	NtCreateFileStatus = NtCreateFile(
		&FileHand, /* out -> handle to file that's created */
		FILE_GENERIC_WRITE,
		&objAtt,
		&ioSB, /* out -> ioStatusBlock */
		NULL,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		NULL, NULL
	);

/*[...SNIP...]*/
LARGE_INTEGER Position;
PLARGE_INTEGER pPosition = NULL;
pPosition = NULL;
Position.LowPart = 0xffffffff /* FILE_WRITE_TO_END_OF_FILE; */
Position.HighPart = -1;
pPosition = &Position;
NtWriteFileStatus = NtWriteFile(
	FileHand, NULL, NULL, NULL, &ioSB,
	(PVOID)TextToWrite, (ULONG)LenTextToWrite, /* Text To write and length of text to write is passed */
	pPosition, NULL
);
/* SNIP */
NtClose(FileHand);
/*[...SNIP...]*/
{% endhighlight %}


## Future Developments/Research
For further research more of the Windows internals functionality would like to be uncovered and experimented with and as a result part 2 of the Windows Internals Microsoft Press series (Russinovich and A. A. 2019) will be acquired and read.

A method to find out the private function callers e.g. RtlpFindAndCommitPages will be valuable, as KERNEL32.DLL, KERNELBASE.DLL and NTDLL.DLL all have Microsoft symbols available, a method will be possible with time invested.

Implementing a buffer checking mechanism for payload detection where calls such as RtlMoveMemory which take a payload from one memory location to another can be hooked, the payload can be added to a detection queue or archive and saved for inspection.

While reading Geoff Chappell’s research about the PEB brought to mind the idea of using the PEB structure as Interprocess control / data sharing in a malicious context. ”Very much more in principle than in practice, data may go into the PEB for sharing between processes more easily than by any formal inter-process
communication.”(Chappell 2022) 

Traditional IPC methods for sharing payloads between processes are listed, provided in the blog by modexp (modexp 2018) and IPC could be an interesting implementation for payload sharing and control.
- Clipboard (WM PASTE)
- Data Copy (WM COPYDATA)
- Named pipes
- Component Object Model (COM)
- Remote Procedure Call (RPC)
- Dynamic Data Exchange (DDE)
	
Instead of using File IO operations for logging capabilities, using Event Tracing for Windows (Microsoft 2021b) which will allow for tracing and logging of events at the application level. TraceLogging enables realtime messages to be provided (Microsoft 2021c).
Overall the project enabled the researcher to perform a range of experiments within windows with the purpose of expanding knowledge and experience.
	

## Credits / Thanks
Secret Club discord people (namazso, JustMagic, Lima X, Matti, Jonaslyk) discussion whenever they were in chat was fucking useful haha reenz0h from sektor7 for CustomGetProcAddress theory