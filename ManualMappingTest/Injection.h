#pragma once
#include <windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

//functionprototypes
using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char * lpLibFilename);
using f_GetProcAddress = UINT_PTR(WINAPI*)(HINSTANCE hModule, const char * lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void * hDLL, DWORD dwReason, void * pReserved);

struct MANUAL_MAPPING_DATA
{
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
	HINSTANCE hMod;
};

//Handle to targetprocess and full path to dll we want to inject
bool ManualMap(HANDLE hProc, const char * szDllFile);
