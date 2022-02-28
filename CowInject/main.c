#include <Ntifs.h>
#include <intrin.h>
#include <ntimage.h>
#include <ntstrsafe.h>

NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);
NTKERNELAPI PPEB NTAPI PsGetProcessWow64Process(PEPROCESS Process);

PVOID g_shellCode = NULL;
ULONG g_injectPid = 2100;

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

VOID allocateMem()
{
	g_shellCode = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'Yci');
	if (g_shellCode)
	{
		PULONG64 PteBase = (PULONG64)GetPTEBase();
		if (PteBase)
		{
			PULONG64 Pte = (PULONG64)MiGetXXXAddress((ULONG64)g_shellCode, PteBase);
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
		}
	}
}

VOID freeMem(ULONG pid)
{
	PEPROCESS pEprocess = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pEprocess)))
	{
		KAPC_STATE kApc = { 0 };
		KeStackAttachProcess(pEprocess, &kApc);
		PULONG64 PteBase = (PULONG64)GetPTEBase();
		if (PteBase)
		{
			PULONG64 Pte = (PULONG64)MiGetXXXAddress((ULONG64)g_shellCode, PteBase);
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
		}
		KeUnstackDetachProcess(&kApc);
		ObDereferenceObject(pEprocess);
	}
}

NTSTATUS InjectProcessX64(ULONG pid)
{
	PEPROCESS pEprocess = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pEprocess)))
	{
		KAPC_STATE kApc = { 0 };
		KeStackAttachProcess(pEprocess, &kApc);
		//allocateMem();

		UNICODE_STRING Kernel32String = RTL_CONSTANT_STRING(L"Kernel32.dll");
		PVOID Kernel32Address = GetUserModule(pEprocess, &Kernel32String, PsGetProcessWow64Process(pEprocess) != 0);//
		
		if (Kernel32Address) //&& g_shellCode)
		{
			PVOID func = GetModuleExport(Kernel32Address, "TlsGetValue");
			PVOID relayAddress = SearchModuleTextNop(Kernel32Address,0x28, 0);
			PVOID shellcodeAddress = SearchModuleTextNop(Kernel32Address, 0x88 + 0x28, 0x28);
			if (func && relayAddress && shellcodeAddress)
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
					ULONG64 tagetAddress = (ULONG64)func + *(ULONG*)((PUCHAR)func + 1) + 5;
					ULONG jneAddress = (ULONG)(tagetAddress - (ULONG64)((PUCHAR)relayAddress + 17) - 6);
					memcpy(checkPid + 13, &pid, sizeof(ULONG));
					memcpy(checkPid + 19, &jneAddress, sizeof(ULONG));
					//memcpy(checkPid + 25, &g_shellCode, sizeof(ULONG64));
					memcpy(checkPid + 25, &shellcodeAddress, sizeof(ULONG64));
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
						0x48, 0x83, 0xEC, 0x26,                 // sub rsp, 0x28
																// do nothing
						0x48, 0x83, 0xC4, 0x26,                 // add rsp, 0x28
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
					memcpy(shellCode + 64, &tagetAddress, sizeof(ULONG64));
					//memcpy(g_shellCode, shellCode, sizeof(shellCode));
					MapSC(shellCode, shellcodeAddress,sizeof(shellCode));

					ULONG jmpRelayAddress = (ULONG)((ULONG64)relayAddress - (ULONG64)func - 5);
					MapSC((PUCHAR)&jmpRelayAddress, (PUCHAR)func + 1, sizeof(ULONG));

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
		freeMem(g_injectPid);
		ExFreePool(g_shellCode);
		g_shellCode = NULL;
	}
	DbgPrint("See you!\n");
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pObj, PUNICODE_STRING pPath)
{
	UNREFERENCED_PARAMETER(pPath);
	pObj->DriverUnload = DriverUnload;
	//DbgBreakPoint();
	InjectProcessX64(g_injectPid);
	return STATUS_SUCCESS;
}