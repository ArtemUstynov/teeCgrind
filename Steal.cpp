#include <stdio.h>
#include <Windows.h>
#include <memory>
#include <iostream>

_PROCESS_INFORMATION Startpausedprocess(char* program, PHANDLE ptr_thread ) // cleaned up a bit, but no RAII
{

    PROCESS_INFORMATION pi;
    if( ptr_thread == nullptr ) return pi ;
    STARTUPINFOA si {} ; // initialize with zeroes.
    si.cb = sizeof(STARTUPINFOA);

    if( !CreateProcessA( program, nullptr, nullptr, nullptr, false, CREATE_SUSPENDED,
                         nullptr, nullptr, std::addressof(si), std::addressof(pi) ) )
    {
        printf( "CreateProcess failed, %lu \n" , GetLastError() ) ;
        *ptr_thread = nullptr ;
        return pi;
    }

    *ptr_thread = pi.hThread;
    return pi;
}

int main(int argc, char **argv)
{
    char program[] = "a.exe" ;
    HANDLE thread = nullptr ;
//    printf( "enter name of your program\n ") ;
//    std::string s;
//    (std::cin >> s).get();
    auto process = Startpausedprocess( program, std::addressof(thread) ) ;

    DWORD PID = process.dwProcessId;
    printf("%lu\n",PID);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProcess)
	{
		printf("Failed to open the debugged app.\n");
		return 1;
	}
	char cStealDLLFileName[] = "teeCgrind.dll";
	DWORD dwStealDLLFileNameLen = sizeof(cStealDLLFileName);
	void * lpDataAddr = VirtualAllocEx(hProcess, NULL, dwStealDLLFileNameLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!lpDataAddr)
	{
		printf("Failed to allocate memory.\n");
		CloseHandle(hProcess);
		return 1;
	}
	SIZE_T szBytesWritten;
	if (!WriteProcessMemory(hProcess, lpDataAddr, cStealDLLFileName, dwStealDLLFileNameLen, &szBytesWritten))
	{
		printf("Failed to write memory.\n");
		CloseHandle(hProcess);
		return 1;
	}
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)(&LoadLibraryA), lpDataAddr, NULL, NULL);
	if (!hThread)
	{
		printf("Failed to create a remote thread.\n");
		CloseHandle(hProcess);
		return 1;
	}

    if( process.hProcess )
    {
        printf( "press enter to execute your program\n ") ;
        getchar();
        ResumeThread(thread) ;

        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread) ;
        CloseHandle(process.hProcess) ;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    printf( "press enter to come to terms with the result\n ") ;
    std::cin.get() ;
	printf("Finished.\n");
	return 0;
}