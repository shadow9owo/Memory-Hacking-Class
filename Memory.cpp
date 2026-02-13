#include "Memory.hpp"

int Memory::GetProcessId(const char* processName)
{
    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(pe32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32First(hSnapshot, &pe32))
    {
        do
        {
            if (_stricmp(pe32.szExeFile, processName) == 0)
            {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

long Memory::GetModuleBase(HANDLE processHandle, std::string& sModuleName)
{
    HMODULE hModules[1024];
    DWORD cbNeeded;

    if (!EnumProcessModules(processHandle, hModules, sizeof(hModules), &cbNeeded))
        return -1;

    char szBuf[MAX_PATH];

    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
    {
        if (GetModuleBaseNameA(processHandle, hModules[i], szBuf, sizeof(szBuf)))
        {
            if (sModuleName == szBuf)
                return (long)hModules[i];
        }
    }

    return -1;
}

BOOL Memory::SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        //printf("LookupPrivilegeValue error: %u\n", GetLastError() );
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        //printf("AdjustTokenPrivileges error: %u\n", GetLastError() );
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        //printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}
BOOL Memory::GetDebugPrivileges(void) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        return FALSE; //std::cout << "OpenProcessToken() failed, error\n>> " << GetLastError() << std::endl;
    //else std::cout << "OpenProcessToken() is OK, got the handle!" << std::endl;

    if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
        return FALSE; //std::cout << "Failed to enable privilege, error:\n>> " << GetLastError() << std::endl;

    return TRUE;
}
int Memory::ReadInt(HANDLE processHandle, long address) {
    if (address == -1)
        return -1;
    int buffer = 0;
    SIZE_T NumberOfBytesToRead = sizeof(buffer); //this is equal to 4
    SIZE_T NumberOfBytesActuallyRead;
    BOOL success = ReadProcessMemory(processHandle, (LPCVOID)address, &buffer, NumberOfBytesToRead, &NumberOfBytesActuallyRead);
    if (!success || NumberOfBytesActuallyRead != NumberOfBytesToRead) {
        std::cout << "Memory Error!" << std::endl;
        DWORD lastError = GetLastError();
        if (lastError != 0)
            std::cout << lastError << std::endl;
        return -1;
    }
    //if (err || NumberOfBytesActuallyRead != NumberOfBytesToRead) {
    //	DWORD lastError = GetLastError();
    //	if (lastError != 0)
    //        std::cout << lastError << std::endl;
    //    std::cout << "blub" << std::endl;
    //}
    return buffer;
}
int Memory::GetPointerAddress(HANDLE processHandle, long startAddress, int offsets[], int offsetCount) {
    if (startAddress == -1)
        return -1;
    int ptr = ReadInt(processHandle, startAddress);
    for (int i = 0; i < offsetCount - 1; i++) {
        ptr += offsets[i];
        ptr = ReadInt(processHandle, ptr);
    }
    ptr += offsets[offsetCount - 1];
    return ptr;
}
int Memory::ReadPointerInt(HANDLE processHandle, long startAddress, int offsets[], int offsetCount) {
    if (startAddress == -1)
        return -1;
    return ReadInt(processHandle, GetPointerAddress(processHandle, startAddress, offsets, offsetCount));
}
float Memory::ReadFloat(HANDLE processHandle, long address) {
    if (address == -1)
        return -1;
    float buffer = 0.0;
    SIZE_T NumberOfBytesToRead = sizeof(buffer); //this is equal to 4
    SIZE_T NumberOfBytesActuallyRead;
    BOOL success = ReadProcessMemory(processHandle, (LPCVOID)address, &buffer, NumberOfBytesToRead, &NumberOfBytesActuallyRead);
    if (!success || NumberOfBytesActuallyRead != NumberOfBytesToRead)
        return -1;
    return buffer;
}
float Memory::ReadPointerFloat(HANDLE processHandle, long startAddress, int offsets[], int offsetCount) {
    if (startAddress == -1)
        return -1;
    return ReadFloat(processHandle, GetPointerAddress(processHandle, startAddress, offsets, offsetCount));
}
char* Memory::ReadText(HANDLE processHandle, long address) {
    if (address == -1)
        return nullptr;
    char buffer = !0;
    char* stringToRead = new char[128];
    SIZE_T NumberOfBytesToRead = sizeof(buffer);
    SIZE_T NumberOfBytesActuallyRead;
    int i = 0;
    while (buffer != 0) {
        BOOL success = ReadProcessMemory(processHandle, (LPCVOID)address, &buffer, NumberOfBytesToRead, &NumberOfBytesActuallyRead);
        if (!success || NumberOfBytesActuallyRead != NumberOfBytesToRead)
            return nullptr;
        stringToRead[i] = buffer;
        i++;
        address++;
    }
    return stringToRead;
}
char* Memory::ReadPointerText(HANDLE processHandle, long startAddress, int offsets[], int offsetCount) {
    if (startAddress == -1)
        return nullptr;
    return ReadText(processHandle, GetPointerAddress(processHandle, startAddress, offsets, offsetCount));
}
