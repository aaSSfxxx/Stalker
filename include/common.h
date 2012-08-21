/*
 * ----------------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <aassfxxx@hackerzvoice.net> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 * ----------------------------------------------------------------------------------
 * This file is part of Stalker (name suggested by Overclok[])
 *
 * Declares common structures used by IPC between injected DLL and Stalker
 */
 
#ifndef COMMON_H_INCLUDED
#define COMMON_H_INCLUDED

#define INTO *(DWORD*)

/** Structure filled by Stalker when the DLL is loaded **/
typedef struct _BOOTSTRAP_INFO {
	char DumpDirectory[1000]; /* Directory to do the dump */
	PVOID executableBase;
	BOOL allowCall;
	BOOL noResume;
} BOOTSTRAP_INFO, *PBOOTSTRAP_INFO;

/** Notifications sent by the injected DLL to the main program **/
typedef struct _SERVICE_PACKET {
	BYTE ServiceCode; /* Service code */
	DWORD Data1;
	DWORD Data2;
	DWORD Data3;
} SERVICE_PACKET, *PSERVICE_PACKET;

#define CODE_GOT_CALL 1
#define CODE_ENDED 2
#endif // COMMON_H_INCLUDED
