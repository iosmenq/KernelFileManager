/*
* Coded by iosmen (C) 2025
*/

#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>

#define EXPORT __declspec(dllexport)

extern "C" {
    EXPORT BOOL DeleteProtectedFile(LPCSTR filePath) {
        DWORD attributes = GetFileAttributesA(filePath);
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            SetFileAttributesA(filePath, FILE_ATTRIBUTE_NORMAL);
        }
        
        if (DeleteFileA(filePath)) {
            return TRUE;
        }
        
        return MoveFileExA(filePath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
    
    EXPORT BOOL IsFileLocked(LPCSTR filePath) {
        HANDLE hFile = CreateFileA(
            filePath,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        
        if (hFile == INVALID_HANDLE_VALUE) {
            return TRUE;
        }
        
        CloseHandle(hFile);
        return FALSE;
    }
    
    EXPORT BOOL IsRunningAsAdmin() {
        BOOL isAdmin = FALSE;
        HANDLE hToken = NULL;
        
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD dwSize;
            
            if (GetTokenInformation(hToken, TokenElevation, &elevation, 
                                    sizeof(elevation), &dwSize)) {
                isAdmin = elevation.TokenIsElevated;
            }
        }
        
        if (hToken) {
            CloseHandle(hToken);
        }
        
        return isAdmin;
    }
}