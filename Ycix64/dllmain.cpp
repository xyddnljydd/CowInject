﻿// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

DWORD __stdcall expStart(LPVOID lpThreadParameter)
{
	MessageBoxA(0, 0, 0, 0);
	return 0;
}

__declspec(dllexport) void Start(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	CreateThread(NULL, NULL, expStart, NULL, NULL, NULL);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

