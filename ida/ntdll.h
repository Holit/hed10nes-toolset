

typedef long KPRIORITY;
typedef struct _UNICODE_STRING {
    unsigned short  Length;
    unsigned short  MaximumLength;
    WORD*  Buffer;
} UNICODE_STRING;
typedef struct _LARGE_INTEGER {
    long long QuadPart;
} LARGE_INTEGER;
typedef struct _SYSTEM_PROCESS_INFORMATION {
    unsigned long NextEntryOffset;
    unsigned long NumberOfThreads;
    unsigned char Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    DWORD UniqueProcessId;
    void* Reserved2;
    unsigned long HandleCount;
    unsigned long SessionId;
    void* Reserved3;
    DWORD PeakVirtualSize;
    DWORD VirtualSize;
    unsigned long Reserved4;
    DWORD PeakWorkingSetSize;
    DWORD WorkingSetSize;
    void* Reserved5;
    DWORD QuotaPagedPoolUsage;
    void* Reserved6;
    DWORD QuotaNonPagedPoolUsage;
    DWORD PagefileUsage;
    DWORD PeakPagefileUsage;
    DWORD PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
