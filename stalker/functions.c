/*
 * ----------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <aassfxxx@hackerzvoice.net> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 * ----------------------------------------------------------------------------------
 * This file is part of Stalker (name suggested by Overclok[])
 *
 * Manages IPC connection between application and DLL
 */

 #include <windows.h>
 #include <stdio.h>
 #include "stalker.h"
 
char origBytes[5];
char bytecode[] =   "\x90" // nop for debugging purposes
					"\x60" // pushad
					"\x68\x04\x03\x02\x01" // push module handle ret
					"\x68\x04\x03\x02\x01" // push PUNICODE_STRING
					"\x6a\x00" // push 0 (Flags)
					"\x6a\x00" // push 0 (Path to file)
					"\xb8\x04\x03\x02\x01" // mov eax,0x01020304 (to replace with our address of LdrLoadDll)
					"\xff\xd0" // call eax
					"\x61" // popad
					"\x68\x04\x03\x02\x01" // push OEP 
					"\xc3";
					

LPZWCREATETHREAD pOrigCreateThread;

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

DWORD WINAPI CreateThreadHook (PHANDLE  	ThreadHandle,
		DWORD  	DesiredAccess,
		PVOID ObjectAttributes,
		HANDLE  	ProcessHandle,
		PVOID  	ClientId,
		PCONTEXT  	ThreadContext,
		PVOID  	UserStack,
		BOOLEAN  	CreateSuspended 
	) 
{
	LPVOID memPage;
    UNICODE_STRING str;
	DWORD temp;
	WCHAR tapz[] = L"trace.dll";
	temp = (DWORD)GetModuleHandle("ntdll.dll");
	temp = (DWORD)GetProcAddress((HANDLE)temp, "LdrLoadDll");
	//17
	*((DWORD*)((int)bytecode + 17)) = temp;
	
	if( !( memPage = VirtualAllocEx(ProcessHandle, NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) ) )
	{
		printf("Coudln't allocate buffer. Error code 0x%x\n", (int)GetLastError());
		exit(-1);
	}
	str.Length = 20;
	str.MaximumLength = 22;
	str.Buffer = (LPVOID)(((int)memPage) + 10);
	*((DWORD*)((int)bytecode + 3)) = (DWORD)(((int)memPage) + 500);
	*((DWORD*)((int)bytecode + 8)) = (DWORD)memPage;
	*((DWORD*)((int)bytecode + 25)) = ThreadContext->Eip;
	// Writes the buffer into RAM
	WriteProcessMemory (ProcessHandle, (LPVOID)memPage, &str, sizeof(UNICODE_STRING), &temp);
	WriteProcessMemory (ProcessHandle, (LPVOID)(((int)memPage) + 10), (HANDLE)tapz, 22, &temp);
	WriteProcessMemory (ProcessHandle, (LPVOID)(((int)memPage) + 50), bytecode, 200, &temp);

	ThreadContext->Eip = (DWORD)(((int)memPage) + 50);
	CopyMemory((LPVOID)pOrigCreateThread, &origBytes, 5);
	return pOrigCreateThread (ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, UserStack, CreateSuspended);
	//28
}
/** This functions creates an named pipe used by Stalker and the hooking DLL **/
 HANDLE CreateIPCPipe() {
	/* Communication pipe */
	HANDLE hNamedPipe = INVALID_HANDLE_VALUE;
	hNamedPipe = CreateNamedPipe(
        "\\\\.\\pipe\\StalkerWPMTrack",        
        PIPE_ACCESS_DUPLEX,        
        PIPE_TYPE_MESSAGE |         // message pipe
        PIPE_READMODE_MESSAGE |     // read as message
        PIPE_WAIT,                  //wait
        PIPE_UNLIMITED_INSTANCES,
        BUFFER_SIZE,
        BUFFER_SIZE,
        NMPWAIT_USE_DEFAULT_WAIT,   // Time-out interval
        NULL                        // Security attributes
    );
	return hNamedPipe;
 }
 
 BOOL WaitForConnection (HANDLE hNamedPipe) {
	if (!ConnectNamedPipe(hNamedPipe, NULL))
    {
		if (ERROR_PIPE_CONNECTED != GetLastError())
        {
            DisconnectNamedPipe(hNamedPipe);
			CloseHandle(hNamedPipe);
            return FALSE;
        }
		return TRUE;
	}
	return FALSE;
}

 void HookCreateThread() {
	DWORD temp, oldProtect;
	// Get address of ZwCreateThread
	temp = (DWORD)GetModuleHandle("ntdll.dll");
	temp = (DWORD)GetProcAddress((HANDLE)temp, "ZwCreateThread");
	
	// Save the address into a global variable
	pOrigCreateThread = (LPZWCREATETHREAD)(temp);
	
	// Build trampoline
	char trampoline[] = "\xe9\x01\x02\x03\x04";
	*((DWORD*)(trampoline + 1)) = (DWORD)CreateThreadHook - (5 + temp);
	
	// Get right to hook
	EnableDebugPrivilege();
	if(!VirtualProtect((PVOID)temp, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		printf("I fail'd faggot \n");
		exit (-1);
	}
	// Save the original bytes and write the trampoline instead
	CopyMemory(origBytes, (PVOID)temp, 5);
	CopyMemory((PVOID)temp, &trampoline, 5);
 }
 
