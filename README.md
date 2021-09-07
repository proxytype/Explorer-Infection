# Explorer-Infection
Infecting explorer.exe with payload to infect new process creation

## Requierments:
Microsoft Detours Library - https://github.com/microsoft/Detours

**Compile:**
1. Unzip source code, open command line and enter to source directory
2. SET DETOURS_TARGET_PROCESSOR=X64
3. C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat
4. NMAKE

Add detours.lib to Linker additional libraries.

**Hooked Functions:**
- NtCreateUserProcess <br>

**Execution**

Finding the process id is not a easy task, we getting the process filename from PRTL_USER_PROCESS_PARAMETERS and compare it to the process list, finding the last process id and inject dll.

**Flow**
- Loader.exe: Inject Payload.dll to explorer.exe.
- Payload.dll: Hook NtCreateUserProcess and inject infection.dll.
- Infection: Dll for continue injection.

