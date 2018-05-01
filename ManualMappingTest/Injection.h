#pragma once
#include <windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

using f_LoadLibrary = HINSTANCE(WINAPI*)(const char * lpLibFilename);
using f_GetProcAddress = UINT_PTR(WINAPI*)(HINSTANCE hModule, const char * lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void * hDLL, DWORD dwReason, void * pReserved);

struct MANUAL_MAPPING_DATA
{
	f_LoadLibrary pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
	HINSTANCE hMod;
};

bool ManualMap(HANDLE hProc, const char * szDllFile);
