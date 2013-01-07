#include <windows.h>
#include <shlobj.h>
#include "resource.h"
#include "stalker.h"

int CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
void SelectDirectory (HWND hwnd);
void SelectFile(HWND hwnd);
DWORD WINAPI StalkerThread (PVOID args);

char szCurDir[MAX_PATH];
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

int WINAPI
WinMain (HINSTANCE hInst,
		 HINSTANCE hPrev,
		 LPSTR lpCmdLine,
		 int nCmdShow) 
{
	GetCurrentDirectory (1024, szCurDir);
	// Let's create a dialog !
	DialogBoxParam (hInst, IDD_STALKERDLG, NULL, DialogProc, 0);
}

int CALLBACK DialogProc(
    HWND hwndDlg,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
) {
	switch (uMsg) {
		case WM_COMMAND:
			switch (wParam) {
				case IDC_SELECTPROCESS:
					SelectFile(hwndDlg);
					break;
				case IDC_SELECTDUMP:
					SelectDirectory(hwndDlg);
					break;
				case IDOK:
					SendDlgItemMessage( hwndDlg, IDC_RESULT, LB_RESETCONTENT, 0, 0);
					EnableWindow(GetDlgItem( hwndDlg, IDOK ), FALSE);
					CreateThread (NULL, NULL, StalkerThread, hwndDlg, NULL, NULL);
					break;
				case IDCANCEL:
					EndDialog(hwndDlg, 0);
				default:
					return 0;
			}
			break;
		case WM_CLOSE:
			EndDialog(hwndDlg, 0);
			break;
		default:
			return 0;
	}
	return 1;
}

DWORD WINAPI StalkerThread (PVOID hwnd) {
	char processPath [MAX_PATH+1];
	char dumpFolder [MAX_PATH+1];
	char szBuff[1024];
	HANDLE hNamedPipe;
	BOOTSTRAP_INFO info;
	DWORD dwRead;
	STARTUPINFOA SI;
    PROCESS_INFORMATION PI;
	SERVICE_PACKET pack;
	BOOL notFinished = TRUE;
	
	if (GetDlgItemText( (HWND)hwnd, IDC_PROCESSPATH, processPath, MAX_PATH) == 0) {
		EnableWindow(GetDlgItem( (HWND)hwnd, IDOK ), TRUE);
		SendDlgItemMessage( (HWND)hwnd, IDC_RESULT, LB_ADDSTRING, 0, (LPARAM)"Fatal: no process given");
		return;
	}
	if (GetDlgItemText( (HWND)hwnd, IDC_SAVEDUMPS, dumpFolder, MAX_PATH) == 0) {
		EnableWindow(GetDlgItem( (HWND)hwnd, IDOK ), TRUE);
		SendDlgItemMessage( (HWND)hwnd, IDC_RESULT, LB_ADDSTRING, 0, (LPARAM)"Fatal: no dump folder given");
		return;
	}
	
	// Cleanup dump folder name
	dwRead = strlen(dumpFolder) - 1;
	if(dumpFolder[dwRead] == '\\') {
		dumpFolder[dwRead] == '\0';
	}
	SendDlgItemMessage( (HWND)hwnd, IDC_RESULT, LB_ADDSTRING, 0, (LPARAM)"Creating IPC pipe...");
	if( (hNamedPipe = CreateIPCPipe()) == INVALID_HANDLE_VALUE) {
		SendDlgItemMessage( (HWND)hwnd, IDC_RESULT, LB_ADDSTRING, 0, (LPARAM)"Fatal: couldn't create pipe.");
		EnableWindow(GetDlgItem( (HWND)hwnd, IDOK ), TRUE);
	}
	SendDlgItemMessage( (HWND)hwnd, IDC_RESULT, LB_ADDSTRING, 0, (LPARAM)"Creating process...");
	/* Creating the process in the suspended way */
	RtlZeroMemory(&SI, sizeof(SI));
    RtlZeroMemory(&PI, sizeof(PI));
    if(!CreateProcess(processPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, szCurDir, &SI, &PI))
	{
		SendDlgItemMessage( (HWND)hwnd, IDC_RESULT, LB_ADDSTRING, 0, (LPARAM)"Fatal: couldn't create process.");
		EnableWindow(GetDlgItem( (HWND)hwnd, IDOK ), TRUE);
	}
	InitializeDLLInjection(&info, PI);
	// Fill structure
	strncpy(info.DumpDirectory, dumpFolder, 1000);
	info.allowCall = (IsDlgButtonChecked ( (HWND)hwnd, IDC_CHECKPROCESSMEM) == BST_CHECKED) ? TRUE : FALSE;
	info.noResume = (IsDlgButtonChecked ( (HWND)hwnd, IDC_CHECKRESUMETHREAD) == BST_CHECKED) ? TRUE : FALSE;
	if( !WaitForConnection(hNamedPipe) ) {
		EnableWindow(GetDlgItem( (HWND)hwnd, IDOK ), TRUE);
	}
	WriteFile (hNamedPipe, &info, sizeof(info), &dwRead, 0);
	SendDlgItemMessage( (HWND)hwnd, IDC_RESULT, LB_ADDSTRING, 0, (LPARAM)"Sending params to process...");
	do {
		if(ReadFile(hNamedPipe, &pack , sizeof(SERVICE_PACKET), &dwRead, 0)) {
			if (pack.ServiceCode == CODE_ENDED) {
				SendDlgItemMessage( (HWND)hwnd, IDC_RESULT, LB_ADDSTRING, 0, (LPARAM)"[SUCCESS] Process terminated");
				notFinished = FALSE;
			}
			else {
				snprintf (szBuff, sizeof(szBuff), "Tried to write %d bytes to address 0x%08x of PID %d", pack.Data2, pack.Data1, pack.Data3);
				SendDlgItemMessage( (HWND)hwnd, IDC_RESULT, LB_ADDSTRING, 0, (LPARAM)szBuff);
				
			}
		}
		else {
			//printf("Subprocess had a problem.\n");
			SendDlgItemMessage( (HWND)hwnd, IDC_RESULT, LB_ADDSTRING, 0, (LPARAM)"Fatal: subprocess had a problem.");
			notFinished = FALSE;
		}
	} while(notFinished);
	FlushFileBuffers(hNamedPipe);
	DisconnectNamedPipe(hNamedPipe);
	CloseHandle(hNamedPipe);
	EnableWindow(GetDlgItem( (HWND)hwnd, IDOK ), TRUE);
	return 0;
}

void SelectDirectory (HWND hwnd)
{
	BROWSEINFO   bi; 
    ZeroMemory(&bi,   sizeof(bi)); 
    char szDisplayName[MAX_PATH] = { '\0' }; 
    
    bi.hwndOwner        =   NULL; 
    bi.pidlRoot         =   NULL; 
    bi.pszDisplayName   =   szDisplayName; 
    bi.lpszTitle        =   "Please select a folder for storing dump files :"; 
    bi.ulFlags          =   BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    bi.lParam           =   NULL; 
    bi.iImage           =   0;  

    LPITEMIDLIST pidl   =   SHBrowseForFolder(&bi);
    char   szPathName[MAX_PATH];
    if   (NULL != pidl)
    {
         BOOL bRet = SHGetPathFromIDList(pidl,szPathName);
         if(FALSE == bRet) {
              MessageBox(hwnd, "Cannot use this directory", "Error", MB_ICONERROR);
			  return;
		}
         SetDlgItemText (hwnd, IDC_SAVEDUMPS, szPathName);
    }
}
void SelectFile(HWND hwnd) 
{
	char szFileName[MAX_PATH];
	ZeroMemory(&szFileName, sizeof(szFileName));
	OPENFILENAME ofn;       // common dialog box structure

	// Initialize OPENFILENAME
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hwnd;
	ofn.lpstrFile = szFileName;
	// Set lpstrFile[0] to '\0' so that GetOpenFileName does not 
	// use the contents of szFile to initialize itself.
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = sizeof(szFileName);
	ofn.lpstrFilter = "Executable files (*.exe)\0*.exe\0All (*.*)\0*.*\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	// Display the Open dialog box. 
	if (GetOpenFileName(&ofn)==TRUE) {
		SetDlgItemText (hwnd, IDC_PROCESSPATH, szFileName);
	}
}