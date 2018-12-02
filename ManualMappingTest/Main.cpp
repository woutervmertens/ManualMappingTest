#include "Injection.h"

const char szDllFile[] = "C:\\Users\\woute\\Source\\repos\\ManualMappingTest\\ManualMappingTest\\Test.dll";
const char szProc[] = "Test Console.exe";

/**
 * Manual mapping workflow:
 * 1. load dll as raw binary data into injector process
 * 2. map sections of dll into target process
 * 3. inject loader shellcode and run it
 * 4. shellcode relocates dll
 * 5. shellcode fixes imports
 * 6. shellcode executes TLS callbacks
 * 7. shellcode calls DllMain
 * 8. cleanup (deallocating memory in targetprocess, deallocating buffers in injector,...)
 */
int main()
{
	//create processentry32 and set the size (we use this as iterator)
	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PE32);

	//create handle snapshot (enumerate all processes)
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		DWORD Err = GetLastError();
		printf("CreateToolhelp32Snapshot failed: 0x%X\n", Err);
		system("PAUSE");
		return 0;
	}

	//Go through the processes and find the one with the same name as our szProc
	DWORD PID = 0;	//ProcessID
	BOOL bRet = Process32First(hSnap, &PE32);
	while (bRet)
	{
		if (!strcmp(szProc, PE32.szExeFile))
		{
			PID = PE32.th32ProcessID;
			break;
		}
		bRet = Process32Next(hSnap, &PE32);
	}

	//Close the snapshot
	CloseHandle(hSnap);

	//Open processhandle
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProc)
	{
		DWORD Err = GetLastError();
		printf("OpenProcess failed: 0x%X\n", Err);
		system("PAUSE");
		return 0;
	}

	//Call injection function
	if (!ManualMap(hProc, szDllFile))
	{
		CloseHandle(hProc);
		printf("Something went wrong\n");
		system("PAUSE");
		return 0;
	}

	//Close processhandle and return
	CloseHandle(hProc);
	return 0;
}