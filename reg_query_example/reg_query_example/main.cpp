#include <windows.h>
#include <tchar.h>
#include <iostream>

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
        std::cerr << "Failed to get buffer size for registry value. Error code: " << result << std::endl;
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

int main() {
    TCHAR* defaultBrowserFullPath = GetDefaultBrowserFullPath();
    _tprintf(_T("Extracted Full Path: %s\n"), defaultBrowserFullPath);
    _tprintf(_T("Extracted File Name: %s\n"), GetFileNameFromFullPath(defaultBrowserFullPath));

    return 0;
}