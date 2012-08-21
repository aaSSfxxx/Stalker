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

int APIENTRY DllMain(HINSTANCE hInst, DWORD dwReason, LPVOID lpReserved) {
	DWORD dwRead;
	HANDLE krnl32;
	SERVICE_PACKET shut;
	char buf[1000];
	switch(dwReason) {
		case DLL_PROCESS_ATTACH:
			//Create the communication pipe
			hFile = CreateFile("\\\\.\\pipe\\StalkerWPMTrack", GENERIC_READ | GENERIC_WRITE, 0 , NULL, OPEN_EXISTING, 0 , NULL);
			ReadFile(hFile,&inf , sizeof(BOOTSTRAP_INFO), &dwRead, 0);
			snprintf(buf, 1000, "%d - %d\n", inf.allowCall, inf.noResume);
			
			//Place hooks for WriteProcessMemory
			krnl32 = GetModuleHandle("kernel32.dll");
			lpWriteProcMem = (LPWRITEPROCESSMEM) GetProcAddress(krnl32, "WriteProcessMemory");
			placeHook(handleWriteProcessMemory, GetProcAddress(krnl32, "WriteProcessMemory"), inf.executableBase);
			placeEATHooking(handleWriteProcessMemory, "WriteProcessMemory", krnl32);
			
			//Place hooks for ResumeThread if asked
			if(inf.noResume == TRUE) {
				placeHook(handleResumeThread, GetProcAddress(krnl32, "ResumeThread"), inf.executableBase);
				placeEATHooking(handleResumeThread, "ResumeThread", krnl32);
			}
			
			break;
		case DLL_PROCESS_DETACH:
			shut.ServiceCode = CODE_ENDED;
			WriteFile(hFile, &shut, sizeof(SERVICE_PACKET), &dwRead, 0);
			break;
	}
	return TRUE;
}
