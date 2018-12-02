#include "Injection.h"

void __stdcall Shellcode(MANUAL_MAPPING_DATA * pData);

bool ManualMap(HANDLE hProc, const char * szDllFile)
{
	BYTE * pSrcData = nullptr;
	IMAGE_NT_HEADERS * pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER * pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER * pOldFileHeader = nullptr;
	BYTE * pTargetBase = nullptr;

	//Check if file actually exists
	if(!GetFileAttributesA(szDllFile))// == INVALID_FILE_ATTRIBUTES)
	{
		printf("file doesn't exist\n");
		return false;
	}

	//Open file
	std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);
	if(File.fail())
	{
		printf("Opening the file failed: %X\n", (DWORD)File.rdstate());
		File.close();
		return false;
	}

	//Get filesize (if < 4kb: fail)
	auto FileSize = File.tellg(); //Note: tellg set filepointer to end of file
	if(FileSize < 0x1000)
	{
		printf("Filesize is invalid.\n");
		File.close();
		return false;
	}

	//Actually start allocating memory
	pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)];
	if(!pSrcData)
	{
		printf("Memory allocating failed\n");
		File.close();
		return false;
	}

	//Reset filepointer to beginning
	File.seekg(0, std::ios::beg);

	//Read and close
	File.read(reinterpret_cast<char*>(pSrcData), FileSize);
	File.close();

	//Check if file is dll
	if(reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) //"MZ", valid PE file = 0x5A4D
	{
		printf("Invalid file\n");
		delete[] pSrcData;
		return false;
	}

	//Fill headers
	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew); //e_lfanew is new NT header
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

	//Check if dll is compatible
#ifdef _WIN64
	if(pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		printf("Invalid platform\n");
		delete[] pSrcData;
		return false;
	}
#else 
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
	{
		printf("Invalid platform\n");
		delete[] pSrcData;
		return false;
	}
#endif

	//Allocate memory in target
	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, reinterpret_cast<void*>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if(!pTargetBase)
	{
		//Can't allocate memory at imageBase -> path a nullptr
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if(!pTargetBase)
		{
			printf("Memory allocating failed (ex) 0x%X\n", GetLastError()); //not enough RAM or anticheat protection
			delete[] pSrcData;
			return false;
		}
	}

	//Start setting up the sections
	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

	//Start mapping the sections
	auto * pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for(UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if(pSectionHeader->SizeOfRawData)//only copy data initialized at start aka not 0
		{
			//write to pTargetBase + relative offset to section
			//source = previously read sourcedata + rawdata offset
			//size = sizeofrawdata
			if(!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
			{
				printf("Can't map sections! 0x%x\n", GetLastError());
				delete[] pSrcData;
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	memcpy(pSrcData, &data, sizeof(data));
	//write pData to beginning of module
	WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr);

	//We can now delete the source data
	delete[] pSrcData;

	//Allocate some memory for shellcode
	void * pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(!pShellcode)
	{
		printf("Memory allocation failed (ex): 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr);

	//Create new thread
	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<PTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);
	if(!hThread)
	{
		printf("Thread creation failed: 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}

	CloseHandle(hThread);

	HINSTANCE hCheck = NULL;
	while(!hCheck)
	{
		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProc, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;
		Sleep(10);
	}
	VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
	return true;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

//Relocation Process
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData)
{
	if (!pData)
		return;

	BYTE * pBase = reinterpret_cast<BYTE*>(pData);
	auto * pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE * LocationDelta = pBase - pOpt->ImageBase;
	if(LocationDelta)
	{
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;
		auto * pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress)
		{
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD * pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
			for(UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
			{
				if(RELOC_FLAG(*pRelativeInfo))
				{
					UINT_PTR * pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	//Import section
	if(pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto * pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDesc->Name)
		{
			char * szMod = reinterpret_cast<char*>(pBase + pImportDesc->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);
			ULONG_PTR * pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->OriginalFirstThunk);
			ULONG_PTR * pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if(IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else
				{
					auto * pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDesc;
		}
	}
	//Call the local storage callbacks
	if(pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto * pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto * pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for(; pCallback && *pCallback; ++pCallback) //while pCallback and *pCallback actually point to a callback
		{
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	//Call dllmain
	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	//Check if injection succeeded
	pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}
