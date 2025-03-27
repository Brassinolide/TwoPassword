#include <windows.h>
#include <iostream>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )

#ifndef STATUS_SUCCESS
typedef LONG NTSTATUS;
typedef NTSTATUS* PNTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

// 未文档化的API
extern "C" NTSTATUS NTAPI ZwSuspendProcess(
    HANDLE ProcessHandle
);

static char buffer[4096] = { 0 };
bool SafeClearMemory(HANDLE hProcess, LPVOID address, SIZE_T size, LPVOID src, SIZE_T src_size, bool random_src = false) {
    SIZE_T written = 0;
    for (size_t offset = 0; offset < size;) {
        if (random_src) {
            if (BCryptGenRandom(NULL, (PUCHAR)src, src_size, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS) {
                return false;
            }
        }
        SIZE_T remaining = size - offset;
        if (remaining >= src_size) {
            if (!WriteProcessMemory(hProcess, (LPVOID)((SIZE_T)address + offset), src, src_size, &written) || written != src_size) {
                return false;
            }
            offset += src_size;
        }
        else {
            if (!WriteProcessMemory(hProcess, (LPVOID)((SIZE_T)address + offset), src, remaining, &written) || written != remaining) {
                return false;
            }
            break;
        }
    }
    return true;
}

//DoD 5220.22-M 方法，写0写1写随机写0写0写1写随机
bool dod_5220_22_m(HANDLE hProcess, PMEMORY_BASIC_INFORMATION mbi) {
    // 正常情况下是7次覆写，但是效率太低了所以缩减到3次
    SecureZeroMemory(buffer, sizeof buffer);
    if (!SafeClearMemory(hProcess, mbi->BaseAddress, mbi->RegionSize, buffer, sizeof buffer)) {
        return false;
    }
    memset(buffer, 0xff, sizeof buffer);
    if (!SafeClearMemory(hProcess, mbi->BaseAddress, mbi->RegionSize, buffer, sizeof buffer)) {
        return false;
    }
    if (!SafeClearMemory(hProcess, mbi->BaseAddress, mbi->RegionSize, buffer, sizeof buffer, true)) {
        return false;
    }
    return true;
    /*
    SecureZeroMemory(buffer, sizeof buffer);
    if (!SafeClearMemory(hProcess, mbi->BaseAddress, mbi->RegionSize, buffer, sizeof buffer)) {
        return false;
    }
    memset(buffer, 0xff, sizeof buffer);
    if (!SafeClearMemory(hProcess, mbi->BaseAddress, mbi->RegionSize, buffer, sizeof buffer)) {
        return false;
    }
    if (!SafeClearMemory(hProcess, mbi->BaseAddress, mbi->RegionSize, buffer, sizeof buffer, true)) {
        return false;
    }
    SecureZeroMemory(buffer, sizeof buffer);
    if (!SafeClearMemory(hProcess, mbi->BaseAddress, mbi->RegionSize, buffer, sizeof buffer)) {
        return false;
    }
    if (!SafeClearMemory(hProcess, mbi->BaseAddress, mbi->RegionSize, buffer, sizeof buffer)) {
        return false;
    }
    memset(buffer, 0xff, sizeof buffer);
    if (!SafeClearMemory(hProcess, mbi->BaseAddress, mbi->RegionSize, buffer, sizeof buffer)) {
        return false;
    }
    if (!SafeClearMemory(hProcess, mbi->BaseAddress, mbi->RegionSize, buffer, sizeof buffer, true)) {
        return false;
    }
    return true;
    */
}

bool SafeTerminateProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        return false;
    }

    if (ZwSuspendProcess(hProcess) != STATUS_SUCCESS) {
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID address = 0;
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE) {
            if (!dod_5220_22_m(hProcess, &mbi)) {
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                return false;
            }
        }
        address = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }

    if (!TerminateProcess(hProcess, 0)) {
        CloseHandle(hProcess);
        return false;
    }
   
    CloseHandle(hProcess);
    return true;
}

std::wstring winapi_get_last_error() {
    wchar_t buffer[1024] = { 0 };
    if (!FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 0, GetLastError(), 0, buffer, sizeof(buffer) / sizeof(wchar_t), 0)) {
        return L"Unknown error";
    }

    return buffer;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        return 1;
    }

    if (!SafeTerminateProcess(atoi(argv[1]))) {
        MessageBoxW(0, winapi_get_last_error().c_str(), L"SafeMemoryCleaner", 0);
        return 1;
    }

    return 0;
}
