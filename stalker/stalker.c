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

void usage(char **argv) {
	printf("Usage: %s [options...] executable\n"
			   "    executable is mandatory and is the executable path\n"
			   "    [-d dumpdir] is optional and specifies where the dumps will be written\n"
			   "Options: \n"
			   "    --allow-call, -a: lets the real WriteProcessMemory call occurs (by default, it is blocked)\n"
			   "    --block-resume-thread, -b: blocks the \"ResumeThread\" calls\n"
			   "    -d dumpdir: defines the directory where dumps will be written in\n", argv[0]);
	exit(0);
	
}

int main (int argc, char** argv) {
	HANDLE hNamedPipe;
	BOOTSTRAP_INFO info;
	DWORD dwRead;
	STARTUPINFOA SI;
    PROCESS_INFORMATION PI;
	SERVICE_PACKET pack;
	int i;
	/* Parsing command line */
	dumpFolder = LocalAlloc(LPTR, 1000);
	// Getting the dump directory
	if(argc < 2) {
		usage(argv);
	}
	info.allowCall = FALSE;
	info.noResume = FALSE;
	// Loop for options
	for(i = 1; i < argc-1; i++) {
		if( strcmp(argv[i], "-d") != 0) {
			GetCurrentDirectory(1000, dumpFolder);
			if( strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--allow-call") == 0) {
				info.allowCall = TRUE;
			}
			else {
				if( strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--block-resume-thread") == 0) {
					info.noResume = TRUE;
				}
				else {
					
					printf("Unrecognized argument %s.\n", argv[i]);
					usage(argv);
				}
			}
		}
		else {
			strncpy(dumpFolder, argv[i + 1], 1000 - 1); // to have a null byte
			i++;
		}
		
	}
	
	
	dwRead = strlen(dumpFolder) - 1;
	if(dumpFolder[dwRead] == '\\') {
		dumpFolder[dwRead] == '\0';
	}
	printf("Dump folder is \"%s\"\n", dumpFolder);
	printf("Creating IPC pipe.\n");
	if( (hNamedPipe = CreateIPCPipe()) == INVALID_HANDLE_VALUE) {
		printf("Couldn't create pipe. Aborting.\n");
		exit(-1);
	}
	printf ("Creating process.\n");
	
	/* Creating the process in the suspended way */
	RtlZeroMemory(&SI, sizeof(SI));
    RtlZeroMemory(&PI, sizeof(PI));
    if(!CreateProcess(argv[argc - 1], NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
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
				printf ("Tried to write %d bytes to address 0x%08x of PID %d\n", pack.Data2, pack.Data1, pack.Data3);
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
