/*
 * ----------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <aassfxxx@hackerzvoice.net> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Poul-Henning Kamp
 * ----------------------------------------------------------------------------------
 * This file is part of Stalker (name suggested by Overclok[])
 *
 * File used in trace.dll
 */

#include <windows.h>
#include "trace.h"

LPVOID futureAddress = 0;
HANDLE hOutFile = 0;

BOOL WINAPI handleWriteProcessMemory(HANDLE hProcess,LPVOID lpBaseAddress,LPCVOID lpBuffer,SIZE_T nSize,SIZE_T *lpNumberOfBytesWritten) {
	DWORD dwRead;
	SERVICE_PACKET shut;
	char fileName[1024];
	if(futureAddress != lpBaseAddress) {
		if(hOutFile != 0) {
			CloseHandle(hOutFile);
		}
		snprintf(fileName, 1024, "%s/dump_%x.dmp", inf.DumpDirectory, lpBaseAddress); 
		hOutFile = CreateFile(fileName , GENERIC_READ | GENERIC_WRITE, 0 , NULL, CREATE_ALWAYS, 0 , NULL);
		shut.ServiceCode = CODE_GOT_CALL;
		shut.Data1 = lpBaseAddress;
		shut.Data2 = nSize;
		shut.Data3 = hProcess;
		WriteFile(hFile, &shut, sizeof(SERVICE_PACKET), &dwRead, 0);
	}
	WriteFile(hOutFile, lpBuffer, nSize, &dwRead, 0);
	futureAddress = lpBaseAddress + nSize;
	if(lpNumberOfBytesWritten != 0) {
		*lpNumberOfBytesWritten = nSize;
	}
	if(!inf.allowCall) {
		return TRUE; // never fail :>
	} 
	else {
		return lpWriteProcMem(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	}
}

DWORD WINAPI handleResumeThread (HANDLE hThread) {
	return TerminateThread (hThread, 1337);
}
