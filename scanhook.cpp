#include "scanhook.h"

AntiHook::AntiHook(DWORD pid)
{
	m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	IsWow64Process(m_hProcess, &isWOW64);
}

AntiHook::~AntiHook()
{
	CloseHandle(m_hProcess);
}


VOID AntiHook::ScanMain()
{	
	if (m_hProcess)
	{
		queryModuleInfo();

		for (modInfoItr = moduleInfo.begin(); modInfoItr != moduleInfo.end(); ++modInfoItr)
		{
			ReadMemoryImage();
			ScanEATHook();
			ScanIATHook();
			FreeMemoryImage();
		}	
	}

}

VOID AntiHook::queryModuleInfo()
{
	if (isWOW64)
	{
		moduleInfo.clear();
		bool ret = 0;
		HANDLE hSnap;
		MODULEENTRY32 me32;
		MODULE_INFO Info;
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, GetProcessId(m_hProcess));
		if (hSnap != INVALID_HANDLE_VALUE)
		{
			me32.dwSize = sizeof(MODULEENTRY32);
			Module32First(hSnap, &me32);
			int err = GetLastError();
			if (Module32First(hSnap, &me32))
			{
				do
				{
					Info.DllBase = me32.modBaseAddr;
					Info.SizeOfImage = me32.modBaseSize;
					wcscpy_s(Info.BaseName, 64, me32.szModule);
					wcscpy_s(Info.FullName, 260, me32.szExePath);
					Info.DiskImage = new BYTE[Info.SizeOfImage];
					peLoad(Info.FullName, Info.DllBase, Info.DiskImage, Info.SizeOfImage);
					moduleInfo.push_back(Info);

				} while (Module32Next(hSnap, &me32));
			}
		}
		
		std::vector<MODULE_INFO> buf1;
		MODULE_INFO Info1;
		HANDLE hSnap1;
		MODULEENTRY32 me321;
		hSnap1 = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(m_hProcess));
		if (hSnap1 != INVALID_HANDLE_VALUE)
		{
			me321.dwSize = sizeof(MODULEENTRY32);
			Module32First(hSnap1, &me321);
			int err = GetLastError();
			if (Module32First(hSnap1, &me321))
			{
				do
				{
					Info.DllBase = me321.modBaseAddr;
					Info.SizeOfImage = me321.modBaseSize;
					wcscpy_s(Info.BaseName, 64, me321.szModule);
					wcscpy_s(Info.FullName, 260, me321.szExePath);
					buf1.push_back(Info);

				} while (Module32Next(hSnap1, &me321));
			}
		}

		for (int a1 = 0; a1 < buf1.size(); a1++)
		{
			moduleInfo.erase(moduleInfo.begin());
		}

		CloseHandle(hSnap1);
		CloseHandle(hSnap);
	}
	else
	{
		moduleInfo.clear();
		bool ret = 0;
		HANDLE hSnap;
		MODULEENTRY32 me32;
		MODULE_INFO Info;
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(m_hProcess));
		if (hSnap != INVALID_HANDLE_VALUE)
		{
			me32.dwSize = sizeof(MODULEENTRY32);
			if (Module32First(hSnap, &me32))
			{
				do
				{
					Info.DllBase = me32.modBaseAddr;
					Info.SizeOfImage = me32.modBaseSize;
					wcscpy_s(Info.BaseName, 64, me32.szModule);
					wcscpy_s(Info.FullName, 260, me32.szExePath);
					Info.DiskImage = new BYTE[Info.SizeOfImage];
					peLoad(Info.FullName, Info.DllBase, Info.DiskImage, Info.SizeOfImage);
					moduleInfo.push_back(Info);

				} while (Module32Next(hSnap, &me32));
			}
		}
		CloseHandle(hSnap);
	}	
}

VOID AntiHook::peLoad(WCHAR* FilePath, LPVOID DllBase, LPVOID Buffer, DWORD BufferSize)
{
	if (isWOW64)
	{
		LPVOID FileBuffer;
		DWORD SectionNum, HeaderSize, DateSize, FileAlignment, SectionAlignment, i;
		HANDLE hFile;
		PE_INFO PeInfo;
		PIMAGE_SECTION_HEADER SectionHead;
		if (Buffer)
		{
			hFile = CreateFile(FilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
			if (hFile != INVALID_HANDLE_VALUE)
			{
				FileBuffer = new BYTE[BufferSize];
				if (FileBuffer)
				{
					if (ReadFile(hFile, FileBuffer, BufferSize, NULL, NULL))
					{
						peAnalysis(FileBuffer, &PeInfo);
						SectionHead = IMAGE_FIRST_SECTION(PeInfo.PeHead32);
						SectionNum = PeInfo.PeHead32->FileHeader.NumberOfSections;
						HeaderSize = PeInfo.PeHead32->OptionalHeader.SizeOfHeaders;
						FileAlignment = PeInfo.PeHead32->OptionalHeader.FileAlignment;
						SectionAlignment = PeInfo.PeHead32->OptionalHeader.SectionAlignment;
						memset(Buffer, 0, BufferSize);
						memcpy(Buffer, FileBuffer, HeaderSize);
						for (i = 0; i < SectionNum; ++i)
						{
							SectionHead[i].SizeOfRawData = AlignSize(SectionHead[i].SizeOfRawData, FileAlignment);
							SectionHead[i].Misc.VirtualSize = AlignSize(SectionHead[i].Misc.VirtualSize, SectionAlignment);
						}
						if (SectionHead[SectionNum - 1].VirtualAddress + SectionHead[SectionNum - 1].SizeOfRawData > BufferSize)
							SectionHead[SectionNum - 1].SizeOfRawData = BufferSize - SectionHead[SectionNum - 1].VirtualAddress;
						for (i = 0; i < SectionNum; ++i)
						{
							DateSize = SectionHead[i].SizeOfRawData;
							memcpy((LPVOID)((UINT64)Buffer + SectionHead[i].VirtualAddress),
								(LPVOID)((UINT64)FileBuffer + SectionHead[i].PointerToRawData), DateSize);
						}
						// buffer dllbase
						baseReloc(Buffer, DllBase);
					}
					delete[] FileBuffer;
				}
			}
			CloseHandle(hFile);
		}
	}
	else
	{
		LPVOID FileBuffer;
		DWORD SectionNum, HeaderSize, DateSize, FileAlignment, SectionAlignment, i;
		HANDLE hFile;
		PE_INFO PeInfo;
		PIMAGE_SECTION_HEADER SectionHead;
		if (Buffer)
		{
			hFile = CreateFile(FilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
			if (hFile != INVALID_HANDLE_VALUE)
			{
				FileBuffer = new BYTE[BufferSize];
				if (FileBuffer)
				{
					if (ReadFile(hFile, FileBuffer, BufferSize, NULL, NULL))
					{
						peAnalysis(FileBuffer, &PeInfo);
						SectionHead = IMAGE_FIRST_SECTION(PeInfo.PeHead);
						SectionNum = PeInfo.PeHead->FileHeader.NumberOfSections;
						HeaderSize = PeInfo.PeHead->OptionalHeader.SizeOfHeaders;
						FileAlignment = PeInfo.PeHead->OptionalHeader.FileAlignment;
						SectionAlignment = PeInfo.PeHead->OptionalHeader.SectionAlignment;
						memset(Buffer, 0, BufferSize);
						memcpy(Buffer, FileBuffer, HeaderSize);
						for (i = 0; i < SectionNum; ++i)
						{
							SectionHead[i].SizeOfRawData = AlignSize(SectionHead[i].SizeOfRawData, FileAlignment);
							SectionHead[i].Misc.VirtualSize = AlignSize(SectionHead[i].Misc.VirtualSize, SectionAlignment);
						}
						if (SectionHead[SectionNum - 1].VirtualAddress + SectionHead[SectionNum - 1].SizeOfRawData > BufferSize)
							SectionHead[SectionNum - 1].SizeOfRawData = BufferSize - SectionHead[SectionNum - 1].VirtualAddress;
						for (i = 0; i < SectionNum; ++i)
						{
							DateSize = SectionHead[i].SizeOfRawData;
							memcpy((LPVOID)((UINT64)Buffer + SectionHead[i].VirtualAddress),
								(LPVOID)((UINT64)FileBuffer + SectionHead[i].PointerToRawData), DateSize);
						}
						// buffer dllbase
						baseReloc(Buffer, DllBase);
					}
					delete[] FileBuffer;
				}
			}
			CloseHandle(hFile);
		}
	}
}

BOOL AntiHook::peAnalysis(LPVOID ImageBase, PPE_INFO Pe)
{
	PIMAGE_DOS_HEADER DosHead;
	if (isWOW64)
	{
		PIMAGE_OPTIONAL_HEADER32 OpitionHead;
		if (ImageBase)
		{
			DosHead = (PIMAGE_DOS_HEADER)ImageBase;
			if (DosHead->e_magic == IMAGE_DOS_SIGNATURE)
			{
				Pe->PeHead32 = (PIMAGE_NT_HEADERS32)((UINT64)ImageBase + DosHead->e_lfanew);
				if (Pe->PeHead32->Signature == IMAGE_NT_SIGNATURE)
				{
					OpitionHead = &(Pe->PeHead32->OptionalHeader);
					Pe->ExportTableRva = (LPVOID)OpitionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
					Pe->ExportSize = OpitionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
					Pe->ImportTableRva = (LPVOID)OpitionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
					Pe->ImportSize = OpitionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
					return TRUE;
				}
			}
		}
	}
	else
	{
		PIMAGE_OPTIONAL_HEADER OpitionHead;
		if (ImageBase)
		{
			DosHead = (PIMAGE_DOS_HEADER)ImageBase;
			if (DosHead->e_magic == IMAGE_DOS_SIGNATURE)
			{
				Pe->PeHead = (PIMAGE_NT_HEADERS)((UINT64)ImageBase + DosHead->e_lfanew);
				if (Pe->PeHead->Signature == IMAGE_NT_SIGNATURE)
				{
					OpitionHead = &(Pe->PeHead->OptionalHeader);
					Pe->ExportTableRva = (LPVOID)OpitionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
					Pe->ExportSize = OpitionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
					Pe->ImportTableRva = (LPVOID)OpitionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
					Pe->ImportSize = OpitionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
					return TRUE;
				}
			}
		}
	}
	
	return FALSE;
}

DWORD AntiHook::AlignSize(UINT Size, UINT Align)
{
	return ((Size + Align - 1) / Align * Align);
}

VOID AntiHook::baseReloc(LPVOID NewImageBase, LPVOID ExistImageBase)
{
	if (isWOW64)
	{
		LONGLONG Diff;
		ULONG TotalCountBytes, SizeOfBlock;
		ULONG_PTR VA;
		UINT64 OriginalImageBase;
		PUSHORT NextOffset = 0;
		PE_INFO PeInfo;
		PIMAGE_BASE_RELOCATION NextBlock;
		peAnalysis(NewImageBase, &PeInfo);
		if (PeInfo.PeHead32 == 0)
			return;
		switch (PeInfo.PeHead32->OptionalHeader.Magic)
		{
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		{
			OriginalImageBase = ((PIMAGE_NT_HEADERS32)PeInfo.PeHead32)->OptionalHeader.ImageBase;
			break;
		}
		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		{
			OriginalImageBase = ((PIMAGE_NT_HEADERS64)PeInfo.PeHead32)->OptionalHeader.ImageBase;
			break;
		}
		default:
			return;
		}
		NextBlock = (PIMAGE_BASE_RELOCATION)((UINT64)NewImageBase +
			PeInfo.PeHead32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		TotalCountBytes = PeInfo.PeHead32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		if (!NextBlock || !TotalCountBytes)
		{
			if (PeInfo.PeHead32->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
				return; //false
			else
				return; //true
		}
		Diff = (UINT64)ExistImageBase - OriginalImageBase;
		while (TotalCountBytes)
		{
			SizeOfBlock = NextBlock->SizeOfBlock;
			TotalCountBytes -= SizeOfBlock;
			SizeOfBlock -= sizeof(IMAGE_BASE_RELOCATION);
			SizeOfBlock /= sizeof(USHORT);
			NextOffset = (PUSHORT)((PCHAR)NextBlock + sizeof(IMAGE_BASE_RELOCATION));
			VA = (UINT64)NewImageBase + NextBlock->VirtualAddress;
			NextBlock = RelocBlock(VA, SizeOfBlock, NextOffset, Diff);
			if (!NextBlock)
				return; //false
		}
		return;	//true
	}
	else
	{
		LONGLONG Diff;
		ULONG TotalCountBytes, SizeOfBlock;
		ULONG_PTR VA;
		UINT64 OriginalImageBase;
		PUSHORT NextOffset = 0;
		PE_INFO PeInfo;
		PIMAGE_BASE_RELOCATION NextBlock;
		peAnalysis(NewImageBase, &PeInfo);
		if (PeInfo.PeHead == 0)
			return;
		switch (PeInfo.PeHead->OptionalHeader.Magic)
		{
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		{
			OriginalImageBase = ((PIMAGE_NT_HEADERS32)PeInfo.PeHead)->OptionalHeader.ImageBase;
			break;
		}
		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		{
			OriginalImageBase = ((PIMAGE_NT_HEADERS64)PeInfo.PeHead)->OptionalHeader.ImageBase;
			break;
		}
		default:
			return;
		}
		NextBlock = (PIMAGE_BASE_RELOCATION)((UINT64)NewImageBase +
			PeInfo.PeHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		TotalCountBytes = PeInfo.PeHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		if (!NextBlock || !TotalCountBytes)
		{
			if (PeInfo.PeHead->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
				return; //false
			else
				return; //true
		}
		Diff = (UINT64)ExistImageBase - OriginalImageBase;
		while (TotalCountBytes)
		{
			SizeOfBlock = NextBlock->SizeOfBlock;
			TotalCountBytes -= SizeOfBlock;
			SizeOfBlock -= sizeof(IMAGE_BASE_RELOCATION);
			SizeOfBlock /= sizeof(USHORT);
			NextOffset = (PUSHORT)((PCHAR)NextBlock + sizeof(IMAGE_BASE_RELOCATION));
			VA = (UINT64)NewImageBase + NextBlock->VirtualAddress;
			NextBlock = RelocBlock(VA, SizeOfBlock, NextOffset, Diff);
			if (!NextBlock)
				return; //false
		}
		return;	//true
	}

}

PIMAGE_BASE_RELOCATION AntiHook::RelocBlock(ULONG_PTR VA, ULONG SizeOfBlock, PUSHORT NextOffset, INT64 Diff)
{
	PUCHAR FixupVA;
	USHORT Offset;
	LONG Temp;
	ULONGLONG Value64;
	while (SizeOfBlock--)
	{
		Offset = *NextOffset & (USHORT)0xfff;
		FixupVA = (PUCHAR)(VA + Offset);
		switch ((*NextOffset) >> 12)
		{
		case IMAGE_REL_BASED_HIGHLOW:
		{
			*(LONG UNALIGNED*)FixupVA += (ULONG)Diff;
			break;
		}
		case IMAGE_REL_BASED_HIGH:
		{
			Temp = *(PUSHORT)FixupVA & 16;
			Temp += (ULONG)Diff;
			*(PUSHORT)FixupVA = (USHORT)(Temp >> 16);
			break;
		}
		case IMAGE_REL_BASED_HIGHADJ:
		{
			if (Offset & 0x2)    // LDRP_RELOCATION_FINAL  0x2
			{
				++NextOffset;
				--SizeOfBlock;
				break;
			}
			Temp = *(PUSHORT)FixupVA & 16;
			++NextOffset;
			--SizeOfBlock;
			Temp += (LONG)(*(PSHORT)NextOffset);
			Temp += (ULONG)Diff;
			Temp += 0x8000;
			*(PUSHORT)FixupVA = (USHORT)(Temp >> 16);
			break;
		}
		case IMAGE_REL_BASED_LOW:
		{
			Temp = *(PSHORT)FixupVA;
			Temp += (ULONG)Diff;
			*(PUSHORT)FixupVA = (USHORT)Temp;
			break;
		}
		case IMAGE_REL_BASED_IA64_IMM64:
		{
			FixupVA = (PUCHAR)((ULONG_PTR)FixupVA & ~(15));
			Value64 = (ULONGLONG)0;
			EXT_IMM64(Value64,
				(PULONG)FixupVA + EMARCH_ENC_I17_IMM7B_INST_WORD_X,
				EMARCH_ENC_I17_IMM7B_SIZE_X,
				EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM7B_VAL_POS_X);
			EXT_IMM64(Value64,
				(PULONG)FixupVA + EMARCH_ENC_I17_IMM9D_INST_WORD_X,
				EMARCH_ENC_I17_IMM9D_SIZE_X,
				EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM9D_VAL_POS_X);
			EXT_IMM64(Value64,
				(PULONG)FixupVA + EMARCH_ENC_I17_IMM5C_INST_WORD_X,
				EMARCH_ENC_I17_IMM5C_SIZE_X,
				EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM5C_VAL_POS_X);
			EXT_IMM64(Value64,
				(PULONG)FixupVA + EMARCH_ENC_I17_IC_INST_WORD_X,
				EMARCH_ENC_I17_IC_SIZE_X,
				EMARCH_ENC_I17_IC_INST_WORD_POS_X,
				EMARCH_ENC_I17_IC_VAL_POS_X);
			EXT_IMM64(Value64,
				(PULONG)FixupVA + EMARCH_ENC_I17_IMM41a_INST_WORD_X,
				EMARCH_ENC_I17_IMM41a_SIZE_X,
				EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41a_VAL_POS_X);
			EXT_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM41b_INST_WORD_X),
				EMARCH_ENC_I17_IMM41b_SIZE_X,
				EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41b_VAL_POS_X);
			EXT_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM41c_INST_WORD_X),
				EMARCH_ENC_I17_IMM41c_SIZE_X,
				EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41c_VAL_POS_X);
			EXT_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_SIGN_INST_WORD_X),
				EMARCH_ENC_I17_SIGN_SIZE_X,
				EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
				EMARCH_ENC_I17_SIGN_VAL_POS_X);
			Value64 += Diff;
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM7B_INST_WORD_X),
				EMARCH_ENC_I17_IMM7B_SIZE_X,
				EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM7B_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM9D_INST_WORD_X),
				EMARCH_ENC_I17_IMM9D_SIZE_X,
				EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM9D_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM5C_INST_WORD_X),
				EMARCH_ENC_I17_IMM5C_SIZE_X,
				EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM5C_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IC_INST_WORD_X),
				EMARCH_ENC_I17_IC_SIZE_X,
				EMARCH_ENC_I17_IC_INST_WORD_POS_X,
				EMARCH_ENC_I17_IC_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM41a_INST_WORD_X),
				EMARCH_ENC_I17_IMM41a_SIZE_X,
				EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41a_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM41b_INST_WORD_X),
				EMARCH_ENC_I17_IMM41b_SIZE_X,
				EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41b_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM41c_INST_WORD_X),
				EMARCH_ENC_I17_IMM41c_SIZE_X,
				EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41c_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_SIGN_INST_WORD_X),
				EMARCH_ENC_I17_SIGN_SIZE_X,
				EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
				EMARCH_ENC_I17_SIGN_VAL_POS_X);
			break;
		}
		case IMAGE_REL_BASED_DIR64:
		{
			*(ULONGLONG UNALIGNED*)FixupVA += Diff;
			break;
		}
		case IMAGE_REL_BASED_MIPS_JMPADDR:
		{
			Temp = (*(PULONG)FixupVA & 0x3ffffff) & 2;
			Temp += (ULONG)Diff;
			*(PULONG)FixupVA = (*(PULONG)FixupVA & ~0x3ffffff) | ((Temp >> 2) & 0x3ffffff);
			break;
		}
		case IMAGE_REL_BASED_ABSOLUTE:
			break;
		default:
			return (PIMAGE_BASE_RELOCATION)NULL;
		}
		++NextOffset;
	}
	return (PIMAGE_BASE_RELOCATION)NextOffset;
}

VOID AntiHook::ReadMemoryImage()
{
	modInfoItr->MemoryImage = new BYTE[modInfoItr->SizeOfImage];
	if (modInfoItr->MemoryImage)
	{
		ReadProcessMemory(m_hProcess, (void*)modInfoItr->DllBase, modInfoItr->MemoryImage, modInfoItr->SizeOfImage, 0);
	}
	return;
}

VOID AntiHook::FreeMemoryImage()
{
	if (modInfoItr->MemoryImage)
	{
		delete[] modInfoItr->MemoryImage;
		modInfoItr->MemoryImage = 0;
	}
}

VOID AntiHook::ScanEATHook()
{
	if (isWOW64)
	{
		LPVOID recove = nullptr;
		char* ApiName;
		WORD* NameOrd;
		DWORD tem, tem1;
		LPVOID ApiAddress, OriApiAddress, Tem;
		DWORD i;
		LPVOID Ent, Eat, OriEat;
		PE_INFO PeInfo = { 0 }, OrigPeInfo = { 0 };
		std::vector<MODULE_INFO>::iterator iter;
		PIMAGE_EXPORT_DIRECTORY ExporTable, OrigExportTable;

		if (peAnalysis((LPVOID)modInfoItr->MemoryImage, &PeInfo) && peAnalysis((LPVOID)modInfoItr->DiskImage, &OrigPeInfo))
		{
			if (PeInfo.ExportSize)
			{
				ExporTable = (PIMAGE_EXPORT_DIRECTORY)((UINT64)modInfoItr->MemoryImage + (UINT64)PeInfo.ExportTableRva);
				OrigExportTable = (PIMAGE_EXPORT_DIRECTORY)((UINT64)modInfoItr->DiskImage + (UINT64)PeInfo.ExportTableRva);
				Eat = (LPVOID)((UINT64)modInfoItr->MemoryImage + ExporTable->AddressOfFunctions);	//指向函数地址rva
				Ent = (LPVOID)((UINT64)modInfoItr->MemoryImage + ExporTable->AddressOfNames);		//指向函数名字rva
				NameOrd = (WORD*)((UINT64)modInfoItr->MemoryImage + ExporTable->AddressOfNameOrdinals);//函数序号rva
				OriEat = (LPVOID)((UINT64)modInfoItr->DiskImage + OrigExportTable->AddressOfFunctions);
				for (i = 0; i < ExporTable->NumberOfNames; ++i)
				{

					if (IsGlobalVar32(OrigPeInfo.PeHead32, ((DWORD*)OriEat)[((WORD*)NameOrd)[i]]))
						continue;

					ApiName = (char*)(((DWORD*)Ent)[i] + (UINT64)modInfoItr->MemoryImage);
					ApiAddress = (LPVOID)(((DWORD*)Eat)[((WORD*)NameOrd)[i]] + (UINT64)modInfoItr->DllBase);	//ram中地址

					OriApiAddress = (LPVOID)(((DWORD*)OriEat)[((WORD*)NameOrd)[i]] + (UINT64)modInfoItr->DllBase);	//disk中地址
					Tem = (LPVOID)(((DWORD*)OriEat)[((WORD*)NameOrd)[i]] + (UINT64)modInfoItr->DiskImage);
					if ((UINT64)Tem >= (UINT64)OrigExportTable && (UINT64)Tem < ((UINT64)OrigExportTable + PeInfo.ExportSize))
						OriApiAddress = FileNameRedirection((char*)Tem);
					else
						ScanInlineHook(ApiName, OriApiAddress);


					if ((((DWORD*)Eat)[NameOrd[i]] != ((DWORD*)OriEat)[NameOrd[i]]) && (OriApiAddress != ApiAddress))
					{
						recove = &((DWORD*)Eat)[((WORD*)NameOrd)[i]];
						UINT64 of = (UINT64)recove - (UINT64)modInfoItr->MemoryImage;
						recove = (LPVOID)(of + (UINT64)modInfoItr->DllBase);

						PROCESS_HOOK_INFO hkinfo;
						hkinfo.eatOffset = (UINT64)OriApiAddress - (UINT64)modInfoItr->DllBase;
						hkinfo.RecoveryAddr = recove;
						ZeroMemory(&hkinfo, sizeof(PROCESS_HOOK_INFO));
						hkinfo.HookType = EatHook;
						hkinfo.OriginalAddress = OriApiAddress;
						hkinfo.HookAddress = ApiAddress;
						MultiByteToWideChar(CP_ACP, 0, ApiName, strlen(ApiName) + 1, hkinfo.HookedApiName, 128);
						wcscpy_s(hkinfo.HookedModule, 64, modInfoItr->BaseName);
						GetModulePathByAddress(ApiAddress, hkinfo.HookLocation);
						hookInfo.push_back(hkinfo);
					}
				}
			}
		}
	}
	else
	{
		LPVOID recove = nullptr;
		char* ApiName;
		WORD* NameOrd;
		DWORD tem, tem1;
		LPVOID ApiAddress, OriApiAddress, Tem;
		DWORD i;
		LPVOID Ent, Eat, OriEat;
		PE_INFO PeInfo = { 0 }, OrigPeInfo = { 0 };
		std::vector<MODULE_INFO>::iterator iter;
		PIMAGE_EXPORT_DIRECTORY ExporTable, OrigExportTable;

		if (peAnalysis((LPVOID)modInfoItr->MemoryImage, &PeInfo) && peAnalysis((LPVOID)modInfoItr->DiskImage, &OrigPeInfo))
		{
			if (PeInfo.ExportSize)
			{
				ExporTable = (PIMAGE_EXPORT_DIRECTORY)((UINT64)modInfoItr->MemoryImage + (UINT64)PeInfo.ExportTableRva);
				OrigExportTable = (PIMAGE_EXPORT_DIRECTORY)((UINT64)modInfoItr->DiskImage + (UINT64)PeInfo.ExportTableRva);
				Eat = (LPVOID)((UINT64)modInfoItr->MemoryImage + ExporTable->AddressOfFunctions);	//指向函数地址rva
				Ent = (LPVOID)((UINT64)modInfoItr->MemoryImage + ExporTable->AddressOfNames);		//指向函数名字rva
				NameOrd = (WORD*)((UINT64)modInfoItr->MemoryImage + ExporTable->AddressOfNameOrdinals);//函数序号rva
				OriEat = (LPVOID)((UINT64)modInfoItr->DiskImage + OrigExportTable->AddressOfFunctions);
				for (i = 0; i < ExporTable->NumberOfNames; ++i)
				{

					if (IsGlobalVar(OrigPeInfo.PeHead, ((DWORD*)OriEat)[((WORD*)NameOrd)[i]]))
						continue;

					ApiName = (char*)(((DWORD*)Ent)[i] + (UINT64)modInfoItr->MemoryImage);
					ApiAddress = (LPVOID)(((DWORD*)Eat)[((WORD*)NameOrd)[i]] + (UINT64)modInfoItr->DllBase);	//ram中地址

					OriApiAddress = (LPVOID)(((DWORD*)OriEat)[((WORD*)NameOrd)[i]] + (UINT64)modInfoItr->DllBase);	//disk中地址
					Tem = (LPVOID)(((DWORD*)OriEat)[((WORD*)NameOrd)[i]] + (UINT64)modInfoItr->DiskImage);
					if ((UINT64)Tem >= (UINT64)OrigExportTable && (UINT64)Tem < ((UINT64)OrigExportTable + PeInfo.ExportSize))
						OriApiAddress = FileNameRedirection((char*)Tem);
					else
						ScanInlineHook(ApiName, OriApiAddress);


					if ((((DWORD*)Eat)[NameOrd[i]] != ((DWORD*)OriEat)[NameOrd[i]]) && (OriApiAddress != ApiAddress))
					{
						recove = &((DWORD*)Eat)[((WORD*)NameOrd)[i]];
						UINT64 of = (UINT64)recove - (UINT64)modInfoItr->MemoryImage;
						recove = (LPVOID)(of + (UINT64)modInfoItr->DllBase);

						PROCESS_HOOK_INFO hkinfo;
						hkinfo.eatOffset = (UINT64)OriApiAddress - (UINT64)modInfoItr->DllBase;
						hkinfo.RecoveryAddr = recove;
						ZeroMemory(&hkinfo, sizeof(PROCESS_HOOK_INFO));
						hkinfo.HookType = EatHook;
						hkinfo.OriginalAddress = OriApiAddress;
						hkinfo.HookAddress = ApiAddress;
						MultiByteToWideChar(CP_ACP, 0, ApiName, strlen(ApiName) + 1, hkinfo.HookedApiName, 128);
						wcscpy_s(hkinfo.HookedModule, 64, modInfoItr->BaseName);
						GetModulePathByAddress(ApiAddress, hkinfo.HookLocation);
						hookInfo.push_back(hkinfo);
					}
				}
			}
		}
	}

}

VOID AntiHook::ScanIATHook()
{
	if (isWOW64)
	{
		LPVOID recove = nullptr;
		char* DllName, * ApiName;
		char OrdinalName[13];
		WCHAR RealDllName[64];
		WORD Ordinal;
		UINT64 ApiAddress, OriApiAddress;
		PIMAGE_THUNK_DATA32 FirstThunk, OriThunk;
		PIMAGE_IMPORT_BY_NAME ByName;
		PE_INFO PeInfo;
		PIMAGE_IMPORT_DESCRIPTOR ImportTable;
		if (peAnalysis(modInfoItr->MemoryImage, &PeInfo))
		{
			if (PeInfo.ImportSize)
			{
				ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((UINT64)modInfoItr->MemoryImage + (UINT64)PeInfo.ImportTableRva);
				while (ImportTable->FirstThunk)
				{
					if (ImportTable->OriginalFirstThunk)
					{
						DllName = (char*)(ImportTable->Name + (UINT64)modInfoItr->MemoryImage);
						OriThunk = (PIMAGE_THUNK_DATA32)(ImportTable->OriginalFirstThunk + (UINT64)modInfoItr->MemoryImage);
						FirstThunk = (PIMAGE_THUNK_DATA32)(ImportTable->FirstThunk + (UINT64)modInfoItr->MemoryImage);
						while (FirstThunk->u1.Function)
						{
							ApiAddress = FirstThunk->u1.Function;

							if (OriThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
							{
								Ordinal = OriThunk->u1.Ordinal & 0xFFFF;
								OriApiAddress = (UINT64)GetProcessAddressLocal(DllName, (char*)Ordinal, RealDllName);
								ApiName = OrdinalName;
							}
							else
							{
								ByName = (PIMAGE_IMPORT_BY_NAME)(OriThunk->u1.AddressOfData + (UINT64)modInfoItr->MemoryImage);
								ApiName = ByName->Name;
								OriApiAddress = (UINT64)GetProcessAddressLocal(DllName, ApiName, RealDllName);
							}
							if (OriApiAddress && (ApiAddress != OriApiAddress))
							{
								recove = &(FirstThunk->u1.Function);
								UINT64 of = (UINT64)recove - (UINT64)modInfoItr->MemoryImage;
								recove = (LPVOID)(of + (UINT64)modInfoItr->DllBase);

								PROCESS_HOOK_INFO info;
								info.HookType = IatHook;
								info.OriginalAddress = (LPVOID)OriApiAddress;
								info.HookAddress = (LPVOID)ApiAddress;
								MultiByteToWideChar(CP_ACP, 0, ApiName, strlen(ApiName) + 1, info.HookedApiName, 128);
								MultiByteToWideChar(CP_ACP, 0, DllName, strlen(DllName) + 1, info.HookedModule, 64);
								GetModulePathByAddress((LPVOID)ApiAddress, info.HookLocation);
								info.RecoveryAddr = recove;
								hookInfo.push_back(info);
							}
							++OriThunk;
							++FirstThunk;
						}
					}
					++ImportTable;
				}
			}
		}
	}
	else
	{
		LPVOID recove = nullptr;
		char* DllName, * ApiName;
		char OrdinalName[13];
		WCHAR RealDllName[64];
		WORD Ordinal;
		UINT64 ApiAddress, OriApiAddress;
		PIMAGE_THUNK_DATA FirstThunk, OriThunk;
		PIMAGE_IMPORT_BY_NAME ByName;
		PE_INFO PeInfo;
		PIMAGE_IMPORT_DESCRIPTOR ImportTable;
		if (peAnalysis(modInfoItr->MemoryImage, &PeInfo))
		{
			if (PeInfo.ImportSize)
			{
				ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((UINT64)modInfoItr->MemoryImage + (UINT64)PeInfo.ImportTableRva);
				while (ImportTable->FirstThunk)
				{
					if (ImportTable->OriginalFirstThunk)
					{
						DllName = (char*)(ImportTable->Name + (UINT64)modInfoItr->MemoryImage);
						OriThunk = (PIMAGE_THUNK_DATA)(ImportTable->OriginalFirstThunk + (UINT64)modInfoItr->MemoryImage);
						FirstThunk = (PIMAGE_THUNK_DATA)(ImportTable->FirstThunk + (UINT64)modInfoItr->MemoryImage);
						while (FirstThunk->u1.Function)
						{
							ApiAddress = FirstThunk->u1.Function;

							if (OriThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
							{
								Ordinal = OriThunk->u1.Ordinal & 0xFFFF;
								OriApiAddress = (UINT64)GetProcessAddressLocal(DllName, (char*)Ordinal, RealDllName);
								ApiName = OrdinalName;
							}
							else
							{
								ByName = (PIMAGE_IMPORT_BY_NAME)(OriThunk->u1.AddressOfData + (UINT64)modInfoItr->MemoryImage);
								ApiName = ByName->Name;
								OriApiAddress = (UINT64)GetProcessAddressLocal(DllName, ApiName, RealDllName);
							}
							if (OriApiAddress && (ApiAddress != OriApiAddress))
							{

								recove = &(FirstThunk->u1.Function);
								UINT64 of = (UINT64)recove - (UINT64)modInfoItr->MemoryImage;
								recove = (LPVOID)(of + (UINT64)modInfoItr->DllBase);

								PROCESS_HOOK_INFO info;
								info.HookType = IatHook;
								info.OriginalAddress = (LPVOID)OriApiAddress;
								info.HookAddress = (LPVOID)ApiAddress;
								MultiByteToWideChar(CP_ACP, 0, ApiName, strlen(ApiName) + 1, info.HookedApiName, 128);
								MultiByteToWideChar(CP_ACP, 0, DllName, strlen(DllName) + 1, info.HookedModule, 64);
								GetModulePathByAddress((LPVOID)ApiAddress, info.HookLocation);
								info.RecoveryAddr = recove;
								hookInfo.push_back(info);
							}
							++OriThunk;
							++FirstThunk;
						}
					}
					++ImportTable;
				}
			}
		}
	}

}

VOID AntiHook::ScanInlineHook(char* ApiName, LPVOID Address)
{
	if (isWOW64)
	{
		LPVOID reco = 0;
		bool IsHook = FALSE;
		LPVOID Dest, Src, HookAddress = 0;
		std::vector<MODULE_INFO>::iterator iter;
		if (GetModuleInfomation(Address, iter))
		{

			Dest = (LPVOID)((UINT64)Address - (UINT64)iter->DllBase + (UINT64)iter->MemoryImage);
			Src = (LPVOID)((UINT64)Address - (UINT64)iter->DllBase + (UINT64)iter->DiskImage);

			if (memcmp(Dest, Src, 15) != 0)
			{
				BYTE byDes[15];
				memcpy(byDes, Dest, 15);
				//jmp   E9 XX XX XX XX
				if (byDes[0] == 0xe8)
				{
					IsHook = TRUE;
				}
			}

			if (IsHook)
			{
				reco = (LPVOID)((UINT64)Dest - (UINT64)iter->MemoryImage + (UINT64)iter->DllBase);

				PROCESS_HOOK_INFO info;
				info.RecoveryAddr = reco;
				memcpy(info.OriByte, Src, 20);
				info.HookType = InlineHook;
				info.HookAddress = Address;
				info.OriginalAddress = Address;
				MultiByteToWideChar(CP_ACP, 0, ApiName, strlen(ApiName) + 1, info.HookedApiName, 128);
				wcscpy_s(info.HookedModule, 64, modInfoItr->BaseName);
				GetModulePathByAddress(Address, info.HookLocation);
				hookInfo.push_back(info);
			}
		}
	}
	else
	{
		LPVOID reco = 0;
		bool IsHook = FALSE;
		LPVOID Dest, Src, HookAddress = 0;
		std::vector<MODULE_INFO>::iterator iter;
		if (GetModuleInfomation(Address, iter))
		{

			Dest = (LPVOID)((UINT64)Address - (UINT64)iter->DllBase + (UINT64)iter->MemoryImage);
			Src = (LPVOID)((UINT64)Address - (UINT64)iter->DllBase + (UINT64)iter->DiskImage);

			if (memcmp(Dest, Src, 15) != 0)
			{
				BYTE byDes[15];
				memcpy(byDes, Dest, 15);
				//15字节跳转 68 xx xx xx xx 48 C7 44 24 04 xx xx xx xx c3
				if (byDes[0] == 0x68 && byDes[5] == 0x48 && byDes[6] == 0xc7 && byDes[7] == 0x44 && byDes[8] == 0x24 && byDes[9] == 0x04
					&& byDes[14] == 0xc3)
				{
					IsHook = TRUE;
				}
				// 12字节  48 B8 XX XX XX XX XX XX XX XX FF E0 
				if (byDes[0] == 0x48 && byDes[1] == 0xb8 && byDes[10] == 0xff && byDes[11] == 0xe0)
				{
					IsHook = TRUE;
				}
				//6字节跳 FF 25 XX XX XX XX
				if (byDes[0] == 0xff || byDes[1] == 0x25)
				{
					IsHook = TRUE;
				}
				//call   E8 XX XX XX XX
				if (byDes[0] == 0xe8)
				{
					IsHook = TRUE;
				}
			}

			if (IsHook)
			{
				reco = (LPVOID)((UINT64)Dest - (UINT64)iter->MemoryImage + (UINT64)iter->DllBase);

				PROCESS_HOOK_INFO info;
				info.RecoveryAddr = reco;
				memcpy(info.OriByte, Src, 20);
				info.HookType = InlineHook;
				info.HookAddress = Address;
				info.OriginalAddress = Address;
				MultiByteToWideChar(CP_ACP, 0, ApiName, strlen(ApiName) + 1, info.HookedApiName, 128);
				wcscpy_s(info.HookedModule, 64, modInfoItr->BaseName);
				GetModulePathByAddress(Address, info.HookLocation);
				hookInfo.push_back(info);
			}
		}
	}

}

BOOL AntiHook::IsGlobalVar(PIMAGE_NT_HEADERS PeHead, DWORD Rva)
{
	WORD SectionNum;
	PIMAGE_SECTION_HEADER Section;
	SectionNum = PeHead->FileHeader.NumberOfSections;
	Section = IMAGE_FIRST_SECTION(PeHead);
	for (int i = 0; i < SectionNum; ++i)
	{
		if ((Section->VirtualAddress <= Rva) && (Rva < (Section->SizeOfRawData + Section->VirtualAddress)))
			return FALSE;
		++Section;
	}
	return TRUE;
}

BOOL AntiHook::IsGlobalVar32(PIMAGE_NT_HEADERS32 PeHead, DWORD Rva)
{
	WORD SectionNum;
	PIMAGE_SECTION_HEADER Section;
	SectionNum = PeHead->FileHeader.NumberOfSections;
	Section = IMAGE_FIRST_SECTION(PeHead);
	for (int i = 0; i < SectionNum; ++i)
	{
		if ((Section->VirtualAddress <= Rva) && (Rva < (Section->SizeOfRawData + Section->VirtualAddress)))
			return FALSE;
		++Section;
	}
	return TRUE;
}

LPVOID AntiHook::FileNameRedirection(char* RedirectionName)
{
	char* ptr, * ProcName;
	char Buffer[128];
	WORD Oridnal;
	WCHAR DllName[128];
	LPVOID ApiAddress = 0;
	std::vector<MODULE_INFO>::iterator iter;
	strcpy_s(Buffer, 128, RedirectionName);
	ptr = strchr(Buffer, '.');
	if (ptr)
	{
		*ptr = 0;
		MultiByteToWideChar(CP_ACP, 0, Buffer, sizeof(Buffer), DllName, 128);

		if (GetModuleInfomation(DllName, iter))
		{
			if (*(char*)(ptr + 1) == '#')
			{
				Oridnal = (WORD)strtoul((char*)(ptr + 2), 0, 10);
				ApiAddress = GetExportByOrdinal((LPVOID)iter->DiskImage, (LPVOID)Oridnal);
			}
			else
			{
				ProcName = (char*)(ptr + 1);
				ApiAddress = GetExportByName((LPVOID)iter->DiskImage, ProcName);
			}
			if (ApiAddress)
				ApiAddress = (LPVOID)((UINT64)ApiAddress - (UINT64)iter->DiskImage + (UINT64)iter->DllBase);
		}
		
	}
	return ApiAddress;
}

BOOL AntiHook::GetModuleInfomation(WCHAR* DllName, std::vector<MODULE_INFO>::iterator& iter)
{
	size_t Len;
	Len = wcslen(DllName);
	for (iter = moduleInfo.begin(); iter != moduleInfo.end(); ++iter)
	{
		if (!_wcsnicmp(iter->BaseName, DllName, Len))
		{
			return TRUE;
		}
	}
	return FALSE;
}

BOOL AntiHook::GetModuleInfomation(LPVOID address, std::vector<MODULE_INFO>::iterator& iter)
{
	
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	VirtualQueryEx(m_hProcess, address, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	address = mbi.AllocationBase;

	if (address)
	{
		for (iter = moduleInfo.begin(); iter != moduleInfo.end(); ++iter)
		{
			if (address == iter->DllBase)
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}

LPVOID AntiHook::GetExportByOrdinal(LPVOID ImageBase, LPVOID Ordinal)
{
	LPVOID ApiAddress = 0;
	DWORD* Eat;
	PE_INFO PeInfo;
	PIMAGE_EXPORT_DIRECTORY ExportTable;
	peAnalysis(ImageBase, &PeInfo);
	if (PeInfo.ExportSize)
	{
		ExportTable = (PIMAGE_EXPORT_DIRECTORY)((UINT64)ImageBase + (UINT64)PeInfo.ExportTableRva);
		Eat = (DWORD*)((UINT64)ImageBase + ExportTable->AddressOfFunctions);
		ApiAddress = (LPVOID)(((Eat[(UINT64)Ordinal - ExportTable->Base] != 0) ? ((UINT64)ImageBase + Eat[(UINT64)Ordinal - ExportTable->Base]) : 0));
		if (((UINT64)ApiAddress >= (UINT64)ExportTable) && ((UINT64)ApiAddress < ((UINT64)ExportTable + PeInfo.ExportSize)))
		{
			ApiAddress = FileNameRedirection((char*)ApiAddress);
			m_IsFromIat = 1;
		}
	}
	return ApiAddress;
}

LPVOID AntiHook::GetExportByName(LPVOID ImageBase, char* ProcName)
{
	int cmp;
	char* ApiName;
	LPVOID ApiAddress = 0;
	WORD Ordinal, * NameOrd;
	DWORD* Ent, * Eat, HigthIndex, LowIndex = 0, MidIndex;

	PE_INFO PeInfo;
	PIMAGE_EXPORT_DIRECTORY ExportTable;
	peAnalysis(ImageBase, &PeInfo);
	if (PeInfo.ExportSize)
	{
		ExportTable = (PIMAGE_EXPORT_DIRECTORY)((UINT64)ImageBase + (UINT64)PeInfo.ExportTableRva);
		Eat = (DWORD*)((UINT64)ImageBase + ExportTable->AddressOfFunctions);
		Ent = (DWORD*)((UINT64)ImageBase + ExportTable->AddressOfNames);
		NameOrd = (WORD*)((UINT64)ImageBase + ExportTable->AddressOfNameOrdinals);
		HigthIndex = ExportTable->NumberOfNames;
		__try
		{
			while (LowIndex <= HigthIndex)
			{


				MidIndex = (LowIndex + HigthIndex) / 2;
				ApiName = (char*)((UINT64)ImageBase + Ent[MidIndex]);
				cmp = strcmp(ProcName, ApiName);
				if (cmp < 0)
				{
					HigthIndex = MidIndex - 1;
					if (MidIndex < 1)
						return 0;
					continue;
				}
				if (cmp > 0)
				{
					LowIndex = MidIndex + 1;
					continue;
				}
				if (cmp == 0)
				{
					Ordinal = NameOrd[MidIndex];
					break;
				}
			}
			if (LowIndex > HigthIndex)
				return 0;
			ApiAddress = (LPVOID)((UINT64)ImageBase + Eat[Ordinal]);
			if ((UINT64)ApiAddress >= (UINT64)ExportTable && ((UINT64)ApiAddress < ((UINT64)ExportTable + PeInfo.ExportSize)))
			{
				ApiAddress = FileNameRedirection((char*)ApiAddress);
				m_IsFromIat = 1;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return 0;
		}
	}
	return ApiAddress;
}

VOID AntiHook::GetModulePathByAddress(LPVOID Address, WCHAR* ModulePath)
{
	

	MEMORY_BASIC_INFORMATION mbi = {0};
	VirtualQueryEx(m_hProcess, Address, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

	Address = mbi.AllocationBase;

	if (Address)
	{
		std::vector<MODULE_INFO>::iterator iter1;
		for (iter1 = moduleInfo.begin(); iter1 != moduleInfo.end(); ++iter1)
		{
			if (iter1->DllBase == Address)
				wcscpy_s(ModulePath, 260, iter1->FullName);
		}
	}

}

LPVOID AntiHook::GetProcessAddressLocal(char* DllName, char* ApiName, WCHAR* RealDllName)
{
	LPVOID ApiAddress = 0;
	WCHAR NameBuffer[64], HostName[64];
	std::vector<MODULE_INFO>::iterator iter;

	MultiByteToWideChar(CP_ACP, 0, DllName, strlen(DllName) + 1, NameBuffer, 64);
	if (HIWORD((DWORD)ApiName))
	{
		if (GetModuleInfomation(NameBuffer, iter))
		{
			ApiAddress = GetExportByName(iter->DiskImage, ApiName);
			if (ApiAddress && !m_IsFromIat)
				ApiAddress = (LPVOID)((UINT64)ApiAddress - (UINT64)iter->DiskImage + (UINT64)iter->DllBase);
			m_IsFromIat = 0;
		}
	}
	else
	{
		if (GetModuleInfomation(NameBuffer, iter))
		{
			ApiAddress = GetExportByOrdinal(iter->DiskImage, ApiName);
			if (ApiAddress && !m_IsFromIat)
				ApiAddress = (LPVOID)((UINT64)ApiAddress - (UINT64)iter->DiskImage + (UINT64)iter->DllBase);
			m_IsFromIat = 0;
		}
	}
	return ApiAddress;
}

std::vector<MODULE_INFO> AntiHook::getModuleInfo()const
{
	return moduleInfo;
}

std::vector<PROCESS_HOOK_INFO> AntiHook::getHookInfo()const
{
	return hookInfo;
}

VOID AntiHook::RecoveryHook(PROCESS_HOOK_INFO info)
{
	switch (info.HookType)
	{
	case IatHook:
		if (isWOW64)
		{
			DWORD oldPage;
			VirtualProtectEx(m_hProcess, info.RecoveryAddr, 4, PAGE_EXECUTE_READWRITE, &oldPage);
			DWORD ad = (DWORD)info.OriginalAddress;
			WriteProcessMemory(m_hProcess, info.RecoveryAddr, &ad, 4, NULL);
			VirtualProtectEx(m_hProcess, info.RecoveryAddr, 4, oldPage, NULL);
		}
		else
		{
			DWORD oldPage;
			VirtualProtectEx(m_hProcess, info.RecoveryAddr, 8, PAGE_EXECUTE_READWRITE, &oldPage);
			WriteProcessMemory(m_hProcess, info.RecoveryAddr, &info.OriginalAddress, 8, NULL);
			VirtualProtectEx(m_hProcess, info.RecoveryAddr, 8, oldPage, NULL);
		}
		break;
	case InlineHook:
		DWORD oldPage1;
		VirtualProtectEx(m_hProcess, info.RecoveryAddr, 20, PAGE_EXECUTE_READWRITE, &oldPage1);
		WriteProcessMemory(m_hProcess, info.HookAddress, info.OriByte, 20, NULL);
		VirtualProtectEx(m_hProcess, info.RecoveryAddr, 20, oldPage1, NULL);
		break;
	case EatHook:
		DWORD oldPage2;
		VirtualProtectEx(m_hProcess, info.RecoveryAddr, 4, PAGE_EXECUTE_READWRITE, &oldPage2);
		WriteProcessMemory(m_hProcess, info.RecoveryAddr, &info.eatOffset, 4, NULL);
		VirtualProtectEx(m_hProcess, info.RecoveryAddr, 4, oldPage2, NULL);
		break;
	default:
		break;
	}

}


