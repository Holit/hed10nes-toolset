#include <stdio.h>
#include <windows.h>
void GetCpuInfo(unsigned int code, unsigned int* a, unsigned int* b, unsigned int* c, unsigned int* d) {
	__asm {
		mov eax, code
		cpuid
		mov edi, a
		mov[edi], eax
		mov edi, b
		mov[edi], ebx
		mov edi, c
		mov[edi], ecx
		mov edi, d
		mov[edi], edx
	}
}
int main() {
	OSVERSIONINFOEX osInfo;
	SYSTEM_INFO systemInfo;

	ZeroMemory(&osInfo, sizeof(OSVERSIONINFOEX));
	osInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((LPOSVERSIONINFO)&osInfo);

	GetSystemInfo(&systemInfo);

	printf("System Version: %d.%d Build %d\n", osInfo.dwMajorVersion, osInfo.dwMinorVersion, osInfo.dwBuildNumber);
	printf("Platform: ");

	switch (osInfo.dwPlatformId) {
	case VER_PLATFORM_WIN32_NT:
		printf("Windows NT\n");
		break;
	case VER_PLATFORM_WIN32_WINDOWS:
		printf("Windows 9x\n");
		break;
	default:
		printf("Unknown\n");
	}

	printf("System Architecture: ");
	switch (systemInfo.wProcessorArchitecture) {
	case PROCESSOR_ARCHITECTURE_AMD64:
		printf("x64 (AMD or Intel)\n");
		break;
	case PROCESSOR_ARCHITECTURE_ARM:
		printf("ARM\n");
		break;
	//case PROCESSOR_ARCHITECTURE_ARM64:
	case 12:
		printf("ARM64\n");
		break;
	case PROCESSOR_ARCHITECTURE_INTEL:
		printf("x86 (Intel)\n");
		break;
	default:
		printf("Unknown\n");
	}
	BOOL isWow64 = FALSE;

	// 使用 IsWow64Process 函数来检测当前进程是否运行在 WOW64 环境中
	if (IsWow64Process(GetCurrentProcess(), &isWow64) && isWow64) {
		printf("Current process is running in WOW64 environment.\n");
	}
	else {
		printf("Current process is not running in WOW64 environment.\n");
	}
	// 检测当前程序的位数
	if (sizeof(void*) == 4) {
		printf("Current program is running as a 32-bit application.\n");
	}
	else if (sizeof(void*) == 8) {
		printf("Current program is running as a 64-bit application.\n");
	}
	else {
		printf("Unable to determine program's bitness.\n");
	}

	// 获取系统信息
	//SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);

	// 检测处理器位数
	if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
		printf("Processor architecture: x64 (AMD or Intel)\n");
	}
	else if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM) {
		printf("Processor architecture: ARM\n");
	}
	else if (systemInfo.wProcessorArchitecture == 12) {
		printf("Processor architecture: ARM64\n");
	}
	else if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
		printf("Processor architecture: x86 (Intel)\n");
	}
	else {
		printf("Processor architecture: Unknown\n");
	}
	BOOL IsBeingDebugged = IsDebuggerPresent();
	if (IsBeingDebugged)
	{
		printf("Program is under debugging.\n");
	}
	else
	{
		printf("Program is not under debugging.\n");
	}
	unsigned int eax, ebx, ecx, edx;

	// 获取厂商信息
	GetCpuInfo(0, &eax, &ebx, &ecx, &edx);
	printf("Vendor ID: %.4s%.4s%.4s\n", (char*)&ebx, (char*)&edx, (char*)&ecx);

	// 获取处理器信息
	GetCpuInfo(1, &eax, &ebx, &ecx, &edx);
	unsigned int stepping = eax & 0xF;
	unsigned int model = (eax >> 4) & 0xF;
	unsigned int family = (eax >> 8) & 0xF;
	unsigned int type = (eax >> 12) & 0x3;
	printf("Stepping: %u\n", stepping);
	printf("Model: %u\n", model);
	printf("Family: %u\n", family);
	printf("Processor Type: %u\n", type);
	unsigned short gs_value = 0;
	unsigned short fs_value = 0;
	int _cpuid = 0;
	// 获取 gs 段寄存器的值
	__asm {
		push eax
		mov gs_value, gs
		mov fs_value, gs
		cpuid
		mov _cpuid, eax
		pop eax
	}

	printf("Value of gs: 0x%04X\n", gs_value);
	printf("Value of fs: 0x%04X\n", fs_value);
	printf("Value of cpuid: 0x%04X\n", _cpuid);

	return 0;
}
