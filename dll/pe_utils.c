/*
 * ----------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <aassfxxx@hackerzvoice.net> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 * ----------------------------------------------------------------------------------
 * This file is part of Stalker (name suggested by Overclok[])
 *
 * File used in trace.dll
 */

#include <windows.h>
#include "trace.h"

/* Crappy functions needed to do EAT hooking */
void EnableDebugPrivilege() {
	TOKEN_PRIVILEGES privilege;
    LUID Luid;
    HANDLE handle1;
    HANDLE handle2;
    handle1 = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    OpenProcessToken(handle1, TOKEN_ALL_ACCESS, &handle2);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid);
    privilege.PrivilegeCount = 1;
    privilege.Privileges[0].Luid = Luid;
    privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(handle2, FALSE, &privilege, sizeof(privilege), NULL, NULL);
    CloseHandle(handle2);
    CloseHandle(handle1);
}

void DisableDebugPrivilege() {
	TOKEN_PRIVILEGES privilege;
    LUID Luid;
    HANDLE handle1;
    HANDLE handle2;
    handle1 = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    OpenProcessToken(handle1, TOKEN_ALL_ACCESS, &handle2);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid);
    privilege.PrivilegeCount = 1;
    privilege.Privileges[0].Luid = Luid;
    privilege.Privileges[0].Attributes = 0;
    AdjustTokenPrivileges(handle2, FALSE, &privilege, sizeof(privilege), NULL, NULL);
    CloseHandle(handle2);
    CloseHandle(handle1);
}
// Provides an IAT hooking
BOOL placeHook(PVOID hookProc, PVOID addressToHook, PVOID imgBase) {
	PVOID import;
    PIMAGE_NT_HEADERS headers = imgBase + INTO (imgBase + 0x3c); // Get PE header
    PIMAGE_IMPORT_DESCRIPTOR desc = imgBase + 
		headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	do {
		import = imgBase + desc->FirstThunk;
        do {
            if(INTO import == (DWORD)addressToHook)
            {
				DWORD oldProtect;
                VirtualProtect(import, 4, PAGE_READWRITE, &oldProtect);
                CopyMemory(import, &hookProc, 4);
                VirtualProtect(import, 4, oldProtect, &oldProtect);
				return TRUE;
            }
            import += 4;
        } while( INTO (import));
        desc = desc + 1;
    } while (desc->Name != 0);
	return FALSE;
}

//Does EAT hooking
BOOL placeEATHooking(PVOID hookProc, LPTSTR functionName, PVOID imgBase) {
	PVOID exports, names, exportAddr;
	int i;
	DWORD relJump;
	PIMAGE_NT_HEADERS headers = imgBase + INTO (imgBase + 0x3c); // Get PE header
    PIMAGE_EXPORT_DIRECTORY desc = imgBase + 
		headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	EnableDebugPrivilege();
	exports = imgBase + desc->AddressOfFunctions;
	names = imgBase + desc->AddressOfNames;
	for(i=0; i < desc->NumberOfNames; i++) {
		if(strcmp((char*)(imgBase + INTO((int)names + 4*i)), functionName) == 0) {
			exportAddr = exports + 4*i;
			DWORD oldProtect;
            if(!VirtualProtect(exportAddr, 4, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				return FALSE;
			}
			relJump = hookProc - imgBase;
            CopyMemory(exportAddr, &relJump, 4);
			if(!VirtualProtect(exportAddr, 4, oldProtect, &oldProtect))
			{
				return FALSE;
			}
		}
		
	}
	DisableDebugPrivilege();
	return TRUE;
}
