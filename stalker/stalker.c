/*
 * ----------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <aassfxxx@hackerzvoice.net> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Poul-Henning Kamp
 * ----------------------------------------------------------------------------------
 * This file is part of Stalker (name suggested by Overclok[])
 *
 * Main file of stalker.exe
 */
 
#include <windows.h>
#include <stdio.h>
#include "stalker.h"

char bytecode[] = 	"`" // pushad
					"jl" // push "l"
					"he.dl" // push "e.dll"
					"htrac" // push "trac"
					"T" // push esp
					"\xb8\x04\x03\x02\x01" // mov eax,0x01020304 (to replace with our address of LoadLibrary
					"\xff\xd0" // call eax
					"\x83\xc4\x0c" // add esp, 0x0c
					"a" // popad
					"\xe9\x04\x03\x02\x01"; // jmp OEP

int main (int argc, char** argv)
{
	HANDLE hNamedPipe;
	BOOTSTRAP_INFO info;
	DWORD dwRead;
	STARTUPINFOA SI;
    PROCESS_INFORMATION PI;
	SERVICE_PACKET pack;
	/* Parsing command line */
	if(argc < 2 || argc > 3) {
		printf("Usage: %s <executable> [dump_folder]\n"
			   "    <executable> is mandatory and is the executable path\n"
			   "    [dump_folder] is optional and specifies where the dumps will be written\n", argv[0]);
		return 0;
	}
	dumpFolder = LocalAlloc(LPTR, 1000);
	if(argc == 2) {
		GetCurrentDirectory(1000, dumpFolder);
	}
	else {
		strncpy(dumpFolder, argv[2], 1000);
	}
	dwRead = strlen(dumpFolder) - 1;
	if(dumpFolder[dwRead] == '\\') {
		dumpFolder[dwRead] == '\0';
	}
	printf("Dump folder is \"%s\"\n", dumpFolder);
	printf("Creating IPC pipe.\n");
	if( (hNamedPipe = CreateIPCPipe()) == INVALID_HANDLE_VALUE) {
		exit(-1);
	}
	
	printf ("Creating process.\n");
	
	/* Creating the process in the suspended way */
	RtlZeroMemory(&SI, sizeof(SI));
    RtlZeroMemory(&PI, sizeof(PI));
    if(!CreateProcess(argv[1], NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
	{
		printf("Unable to create process. Error code 0x%08x\n", (int)GetLastError());
		exit(-1);
	}
	InitializeDLLInjection(&info, PI);
	
	// Fill structure
	strncpy(info.DumpDirectory, dumpFolder, 1000);
	
	if( !WaitForConnection(hNamedPipe) ) {
		exit(-1);
	}
	WriteFile (hNamedPipe, &info, sizeof(info), &dwRead, 0);
	
	BOOL notFinished = TRUE;
	do {
		if(ReadFile(hNamedPipe, &pack , sizeof(SERVICE_PACKET), &dwRead, 0)) {
			if (pack.ServiceCode == CODE_ENDED) {
				printf ("Subprocess exited.\n");
				notFinished = FALSE;
			}
			else {
				printf ("Tried to write %d bytes to address 0x%08x of process %d\n", pack.Data2, pack.Data1, pack.Data3);
			}
		}
		else {
			printf("Subprocess had a problem.\n");
			notFinished = FALSE;
		}
	} while(notFinished);
	FlushFileBuffers(hNamedPipe);
	DisconnectNamedPipe(hNamedPipe);
	CloseHandle(hNamedPipe);
	return 0;
}