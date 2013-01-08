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
 
 char bytecode[] = 	"\x90" // nop for debugging purposes
					"\x60" // pushad
					"\x6a\x6c" // push "l"
					"\x68\x65\x2e\x64\x6c" // push "e.dll"
					"\x68\x74\x72\x61\x63" // push "trac"
					"\x54" // push esp
					"\xb8\x04\x03\x02\x01" // mov eax,0x01020304 (to replace with our address of LoadLibrary
					"\xff\xd0" // call eax
					"\x83\xc4\x0c" // add esp, 0x0c
					"\x61" // popad
					"\xe9\x04\x03\x02\x01"; // jmp OEP

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
	if (hNamedPipe == INVALID_HANDLE_VALUE)
    {
		printf("CreateNamedPipe failed\n");
    }
	return hNamedPipe;
 }
 
 BOOL WaitForConnection (HANDLE hNamedPipe) {
	if (!ConnectNamedPipe(hNamedPipe, NULL))
    {
		if (ERROR_PIPE_CONNECTED != GetLastError())
        {
            printf("ConnectNamedPipe failed\n");
			DisconnectNamedPipe(hNamedPipe);
			CloseHandle(hNamedPipe);
            return FALSE;
        }
	}
	return TRUE;
}
/** This function prepares the target executable to load our DLL **/
 void InitializeDLLInjection(PBOOTSTRAP_INFO pInformation, PROCESS_INFORMATION PI) {
	LPVOID hOEP, hNewOP;
	HANDLE hLoadLibrary;
	PCONTEXT CTX = VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE);

	/* Write the real address of LoadLibrary */
	hLoadLibrary = GetModuleHandle("kernel32.dll");
	hLoadLibrary = GetProcAddress(hLoadLibrary, "LoadLibraryA");
	*(DWORD*)(bytecode + 16) = (DWORD)hLoadLibrary;
	
	/* Get the context of the main thread */
	CTX->ContextFlags = CONTEXT_FULL;
	GetThreadContext(PI.hThread, CTX);
	hOEP = (LPVOID)CTX->Eax;
	//pInformation->executableBase = INTO (CTX->Ebx + 8);
	ReadProcessMemory(PI.hProcess, (LPVOID)((int)(CTX->Ebx) + 8), &pInformation->executableBase , 4, NULL);
	if( !( hNewOP = VirtualAllocEx(PI.hProcess, NULL, 50, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) ) )
	{
		printf("Coudln't allocate buffer. Error code 0x%x\n", (int)GetLastError());
		exit(-1);
	}
	/* Compute offset to relative jump and replacing it */
	DWORD relJump = hOEP - (hNewOP + 26 + 5);
	*(DWORD*)(bytecode + 27) = relJump;
	WriteProcessMemory(PI.hProcess, hNewOP, bytecode, 40, &relJump); // don't want to pollute the stack with another var
	CTX->Eax = (DWORD)hNewOP;
	SetThreadContext(PI.hThread, CTX);
	ResumeThread(PI.hThread);
 }
