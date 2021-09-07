// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

DWORD WINAPI createMessageBox(LPCWSTR lpParam) {
    MessageBox(NULL, lpParam, L"Dll says:", MB_OK);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
        createMessageBox(L"Injected To Thread!");
        break;
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        createMessageBox(L"Deatch From Process!");
        break;
    }
    return TRUE;
}
