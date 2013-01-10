/*
 * ----------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <aassfxxx@hackerzvoice.net> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 * ----------------------------------------------------------------------------------
 * This file is part of Stalker (name suggested by Overclok[])
 *
 * Main file of stalker.exe
 */
 
#ifndef _STALKER_H_INCLUDE
#define _STALKER_H_INCLUDE

#include "common.h"

HANDLE CreateIPCPipe();
BOOL WaitForConnection (HANDLE hNamedPipe);
void HookCreateThread();

typedef DWORD (*LPZWCREATETHREAD) (PHANDLE ThreadHandle, DWORD DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, 
                                   PVOID ClientId, PCONTEXT ThreadContext, PVOID UserStack, BOOLEAN CreateSuspended);

typedef struct _LSA_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

char *dumpFolder;
char bytecode[1024];
#define BUFFER_SIZE 4096

#endif
