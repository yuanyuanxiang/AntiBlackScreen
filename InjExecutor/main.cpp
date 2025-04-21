#include <windows.h> 
#include <tlhelp32.h>
#include "logger.h"

#ifdef _WIN64
#include "AntiBlackScreen_x64.cpp"
const unsigned char* dllSrc = AntiBlackScreen_x64_dll;
const unsigned int dllSize = AntiBlackScreen_x64_dll_len;
#else
#include "AntiBlackScreen.cpp"
const unsigned char* dllSrc = AntiBlackScreen_dll;
const unsigned int dllSize = AntiBlackScreen_dll_len;
#endif

// Check if the process is 64bit.
bool IsProcess64Bit(HANDLE hProcess, BOOL& is64Bit)
{
	BOOL bWow64 = FALSE;
	typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS2)(HANDLE, USHORT*, USHORT*);
	HMODULE hKernel = GetModuleHandleA("kernel32.dll");

	LPFN_ISWOW64PROCESS2 fnIsWow64Process2 = hKernel ? 
		(LPFN_ISWOW64PROCESS2)GetProcAddress(hKernel, "IsWow64Process2") : nullptr;

	if (fnIsWow64Process2)
	{
		USHORT processMachine = 0, nativeMachine = 0;
		if (fnIsWow64Process2(hProcess, &processMachine, &nativeMachine))
		{
			is64Bit = (processMachine == IMAGE_FILE_MACHINE_UNKNOWN) && (nativeMachine == IMAGE_FILE_MACHINE_AMD64);
			return true;
		}
	}
	else
	{
		// Old system use IsWow64Process
		if (IsWow64Process(hProcess, &bWow64))
		{
			is64Bit = sizeof(void*)==8 ? TRUE : !bWow64;
			return true;
		}
	}
	return false;
}

// Find process id by name.
DWORD GetProcessIdByName(const std::string& procName) {
	DWORD pid = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 pe32 = { sizeof(pe32) };
		if (Process32First(hSnap, &pe32)) {
			do {
				if (_stricmp(pe32.szExeFile, procName.c_str()) == 0) {
					pid = pe32.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &pe32));
		}
		CloseHandle(hSnap);
	}
	return pid;
}

// Check if it's able to inject.
HANDLE CheckProcess(DWORD pid) {
	HANDLE hProcess = OpenProcess(
		PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, 
		FALSE, pid);
	if (!hProcess) {
		Mprintf("OpenProcess failed. PID: %d\n", pid);
		return nullptr;
	}

	// Check process and system architecture.
	BOOL targetIs64Bit = FALSE;
	BOOL success = IsProcess64Bit(hProcess, targetIs64Bit);
	if (!success) {
		Mprintf("Get architecture failed \n");
		CloseHandle(hProcess);
		return nullptr;
	}
	const BOOL selfIs64Bit = sizeof(void*) == 8;
	if (selfIs64Bit != targetIs64Bit) {
		Mprintf("[Unable inject] Injector is %s, Target process is %s\n", (selfIs64Bit ? "64bit" : "32bit"), 
			(targetIs64Bit ? "64bit" : "32bit") );
		CloseHandle(hProcess);
		return nullptr;
	}
	return hProcess;
}

// Inject dll to target process.
bool InjectDLL(DWORD pid, const BYTE* pDllBuffer, int dllSize) {
	HANDLE hProcess = CheckProcess(pid);
	if (!hProcess)
		return false;

	char buffer[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	std::string::size_type pos = std::string(buffer).find_last_of("\\/");
	auto dllLocation = std::string(buffer).substr(0, pos) + "\\";
	auto dllPath = dllLocation + (sizeof(void*) == 8 ? "AntiBlackScreen_x64.dll" : "AntiBlackScreen.dll");
	std::ifstream file(dllPath);
	if (!file.good()) {
		std::ofstream out(dllPath, std::ios::binary);
		if (!out) {
			Mprintf("Unable to open: %s\n", dllPath.c_str());
			CloseHandle(hProcess);
			return false;
		}
		out.write(reinterpret_cast<const char*>(pDllBuffer), dllSize);
		out.close();
	}

	// Alloc memory in target process.
	size_t size = (dllPath.length() + 1) * sizeof(char);
	LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT, PAGE_READWRITE);
	if (!remoteMem) {
		Mprintf("VirtualAllocEx failed \n");
		CloseHandle(hProcess);
		return false;
	}

	// Write DLL path in target process.
	if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), size, nullptr)) {
		Mprintf("WriteProcessMemory failed \n");
		VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// Get LoadLibraryA address.
	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
	LPTHREAD_START_ROUTINE pLoadLibraryA = kernel32 ? (LPTHREAD_START_ROUTINE)
		GetProcAddress(kernel32, "LoadLibraryA") : nullptr;

	if (!pLoadLibraryA) {
		Mprintf("GetProcAddress LoadLibraryA failed \n");
		VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// Create a remote thread to call LoadLibraryA.
	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, pLoadLibraryA, remoteMem, 0, nullptr);
	if (!hThread) {
		Mprintf("CreateRemoteThread failed \n");
		VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	Mprintf("Inject success! \n");
	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	return true;
}

BOOL ConvertToShellcode(LPVOID inBytes, DWORD length, DWORD userFunction, LPVOID userData, DWORD userLength, 
	DWORD flags, LPSTR& outBytes, DWORD& outLength);

bool MakeShellcode(LPBYTE& compressedBuffer, int& ulTotalSize, LPBYTE originBuffer, int ulOriginalLength) {
	if (originBuffer[0] == 'M' && originBuffer[1] == 'Z') {
		LPSTR finalShellcode = NULL;
		DWORD finalSize;
		if (!ConvertToShellcode(originBuffer, ulOriginalLength, NULL, NULL, 0, 0x1, finalShellcode, finalSize)) {
			return false;
		}
		compressedBuffer = new BYTE[finalSize];
		ulTotalSize = finalSize;

		memcpy(compressedBuffer, finalShellcode, finalSize);
		free(finalShellcode);

		return true;
	}
	return false;
}

// Inject shell code to target process.
bool InjectShellcode(DWORD pid, const BYTE* pDllBuffer, int dllSize) {
	HANDLE hProcess = CheckProcess(pid);
	if (!hProcess)
		return false;

	// Convert DLL -> Shell code.
	LPBYTE shellcode = NULL;
	int len = 0;
	if (!MakeShellcode(shellcode, len, (LPBYTE)pDllBuffer, dllSize)) {
		Mprintf("MakeShellcode failed \n");
		CloseHandle(hProcess);
		return false;
	}

	LPVOID remoteBuffer = VirtualAllocEx(hProcess, nullptr, len, MEM_COMMIT, PAGE_READWRITE);
	if (!remoteBuffer) {
		Mprintf("VirtualAllocEx failed \n");
		CloseHandle(hProcess);
		return false;
	}

	if (!WriteProcessMemory(hProcess, remoteBuffer, shellcode, len, nullptr)) {
		Mprintf("WriteProcessMemory failed \n");
		VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		delete[] shellcode;
		return false;
	}
	delete[] shellcode;

	// Shell code entry.
	LPTHREAD_START_ROUTINE entry = reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<ULONG_PTR>(remoteBuffer));

	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, entry, remoteBuffer, 0, nullptr);
	if (!hThread) {
		Mprintf("CreateRemoteThread failed \n");
		VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	Mprintf("Inject success! \n");
	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return true;
}


bool InjectToProcessByName(const std::string& processName, bool shellcodeInj) {
	auto pid = GetProcessIdByName(processName);
	if (pid == 0) {
		Mprintf("Can't find process: %s\n", processName.c_str());
		return false;
	}

	return shellcodeInj ? InjectShellcode(pid, dllSrc, dllSize) : InjectDLL(pid, dllSrc, dllSize);
}

// Usage: InjExecutor.exe -p notepad.exe shellcode
int main(int argc, char* argv[])
{
	std::string targetProcessName;
	bool shellcode = false;

	for (int i = 1; i < argc; ++i) {
		std::string arg = argv[i];

		if (arg == "-p" && i + 1 < argc) {
			targetProcessName = argv[++i];
		}
		else if (arg == "--shellcode") {
			shellcode = true;
		}
		else {
			Mprintf("Unknown parameter: %s\n", arg.c_str());
			return 0;
		}
	}
	if (targetProcessName.empty()) {
		Mprintf("Parameter required: -p\n");
		return 0;

	}

	bool ret = InjectToProcessByName(targetProcessName, shellcode);

	Sleep(3000);
	return ret ? 0 : -1;
}
