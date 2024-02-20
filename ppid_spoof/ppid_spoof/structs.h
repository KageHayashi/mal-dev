#pragma once
#include<Windows.h>

struct PROCESS_BASIC_INFORMATION {
	PINT Reserved1;
	PINT PebBaseAddress;
	PINT Reserved2[2];
	PINT UniqueProcessId;
	PINT Reserved3;
};

typedef NTSTATUS(WINAPI* _NtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
	);

typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);

typedef NTSTATUS(WINAPI* _NtQuerySystemInformation)(
	DWORD SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);