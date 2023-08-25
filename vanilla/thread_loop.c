#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <TlHelp32.h>

int checkThread()
{

	DWORD currentProcessId = GetCurrentProcessId();
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("Error creating snapshot: %lu\n", GetLastError());
		return -1;
	}

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hSnapshot, &threadEntry)) {
		printf("Error getting first thread: %lu\n", GetLastError());
		CloseHandle(hSnapshot);
		return -1;
	}
	int d = GetLastError();
	int thCount = 0;
	printf("Threads in current process (Process ID: %lu):\n", currentProcessId);
	printf("ID    \tEip             \tState     \tSuspended Count\n---------------------------\n");
	do {
		if (threadEntry.th32OwnerProcessID == currentProcessId) {
			HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, threadEntry.th32ThreadID);
			if (hThread) {
				thCount++;
				CONTEXT threadContext;
				threadContext.ContextFlags = CONTEXT_CONTROL;
				if (GetThreadContext(hThread, &threadContext)) {
					printf("0x%04x\t", threadEntry.th32ThreadID);
					printf("0x%016I64X\t", threadContext.Rip);
					printf("%10s\t", (threadEntry.dwSize >= FIELD_OFFSET(THREADENTRY32, dwSize) + sizeof(threadEntry.dwSize) + sizeof(threadEntry.th32ThreadID) + sizeof(threadEntry.tpBasePri)) ?
						(threadEntry.th32ThreadID == GetCurrentThreadId() ? "Executive" : "Running  ") : "Unknown  ");
					printf("%lu\n", threadEntry.cntUsage);
				}
				else
				{
					int dwError = GetLastError();
				}
				CloseHandle(hThread);
			}
		}
	} while (Thread32Next(hSnapshot, &threadEntry));

	CloseHandle(hSnapshot);
	return thCount;
}
DWORD WINAPI ThreadFunction(LPVOID lpParam)
{

	do {
		*(BOOL*)lpParam = IsDebuggerPresent();
	} while (true);
	return 0;
}

int main(int argc, char** argv, char** env) {
	HANDLE hThread;
	DWORD threadId;
	BOOL debugger_attached = FALSE;
	hThread = CreateThread(NULL, 0, ThreadFunction, &debugger_attached, 0, &threadId);
	do 
	{
		Sleep(2000);
		system("cls");
		int thCount = checkThread();
		printf(" %d Thread in total%s\n",thCount,debugger_attached?", debugger attached":"");
		
	} while (true);
	return 0;
}
