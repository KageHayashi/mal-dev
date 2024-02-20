#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <psapi.h>

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

int _tmain(int argc, _TCHAR* argv[]) {
    if (argc != 2) {
        _tprintf(_T("Usage: %s <process_name>\n"), argv[0]);
        return 1;
    }

    DWORD topParentProcessId = GetTopParentProcessId(argv[1]);

    if (topParentProcessId != 0) {
        _tprintf(_T("Top Parent Process ID: %d\n"), topParentProcessId);
    }
    else {
        _tprintf(_T("Process with name %s not found.\n"), argv[1]);
    }

    return 0;
}
