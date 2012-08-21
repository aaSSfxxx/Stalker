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
 
#ifndef TRACE_H_INCLUDED
#define TRAC_8H_INCLUDED

#include "common.h"

// PE utils functions (defined in pe_utils.c)
BOOL placeHook(PVOID hookProc, PVOID addressToHook, PVOID hInstance);
BOOL placeEATHooking(PVOID hookProc, LPTSTR functionName, PVOID imgBase);

// Hook functions (defined in hook.c)
BOOL WINAPI handleWriteProcessMemory(HANDLE hProcess,LPVOID lpBaseAddress,LPCVOID lpBuffer,SIZE_T nSize,SIZE_T *lpNumberOfBytesWritten);
DWORD WINAPI handleResumeThread (HANDLE hThread);

// Variables used by the DLL
HANDLE hFile; // handle of named pipe
BOOTSTRAP_INFO inf; // informations sent by Stalker
	
#endif