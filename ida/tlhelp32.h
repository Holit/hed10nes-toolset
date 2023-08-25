	typedef struct tagPROCESSENTRY32
	{
		unsigned long   dwSize;
		unsigned long   cntUsage;
		unsigned long   th32ProcessID;          // this process
		unsigned __int64 th32DefaultHeapID;
		unsigned long   th32ModuleID;           // associated exe
		unsigned long   cntThreads;
		unsigned long   th32ParentProcessID;    // this process's parent process
		long    pcPriClassBase;         // Base priority of process's threads
		unsigned long   dwFlags;
		char    szExeFile[260];    // Path
	} PROCESSENTRY32;
	typedef PROCESSENTRY32* PPROCESSENTRY32;
	typedef PROCESSENTRY32* LPPROCESSENTRY32;