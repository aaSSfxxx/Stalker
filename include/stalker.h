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
void InitializeDLLInjection(PBOOTSTRAP_INFO pInformation, PROCESS_INFORMATION PI);

char *dumpFolder;
char bytecode[];
#define BUFFER_SIZE 4096

#endif
