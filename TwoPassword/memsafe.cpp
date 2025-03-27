#include "memsafe.h"
#include "setting.h"

byteptr make_byteptr(size_t total_size) {
    return byteptr(new uint8_t[total_size](), ZeroDeleter(total_size));
}

bool InstallInlineHook32(void* target, void* detour) {
    if (!target || !detour) {
        return false;
    }

    DWORD oldProtect;
    if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    BYTE jmp[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
    *(DWORD*)(jmp + 1) = (DWORD)((BYTE*)detour - (BYTE*)target - 5);
    memcpy(target, jmp, 5);

    VirtualProtect(target, 5, oldProtect, &oldProtect);
    return true;
}

bool InstallInlineHook64(void* target, void* detour) {
    if (!target || !detour) {
        return false;
    }

    DWORD oldProtect;
    if (!VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    BYTE jmp[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    *(ULONGLONG*)(jmp + 6) = (ULONGLONG)detour;
    memcpy(target, jmp, 14);

    VirtualProtect(target, 14, oldProtect, &oldProtect);
    return true;
}

#ifdef _WIN64
#define InstallInlineHook InstallInlineHook64
#else
#define InstallInlineHook InstallInlineHook32
#endif

BOOL WINAPI MyHeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
    return TRUE;
}

BOOL WINAPI MyVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    return TRUE;
}

HGLOBAL WINAPI MyGlobalFree(HGLOBAL hMem) {
    return NULL;
}

HLOCAL WINAPI MyLocalFree(HLOCAL hMem) {
    return NULL;
}

BOOL WINAPI MyVirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    return TRUE;
}

BOOL WINAPI MyHeapDestroy(HANDLE hHeap) {
    return TRUE;
}

void WINAPI MyCoTaskMemFree(LPVOID pv) {
    return;
}

void _cdecl Myfree(void* _Block) {
    return;
}

void MySysFreeString(BSTR bstrString) {
    return;
}

BOOLEAN WINAPI MyRtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID HeapBase) {
    return TRUE;
}

void disable_memfree() {
    InstallInlineHook(HeapFree, MyHeapFree);
    InstallInlineHook(VirtualFree, MyVirtualFree);
    InstallInlineHook(GlobalFree, MyGlobalFree);
    InstallInlineHook(LocalFree, MyLocalFree);
    InstallInlineHook(VirtualFreeEx, MyVirtualFreeEx);
    InstallInlineHook(HeapDestroy, MyHeapDestroy);
    InstallInlineHook(CoTaskMemFree, MyCoTaskMemFree);
    InstallInlineHook(free, Myfree);
    InstallInlineHook(SysFreeString, MySysFreeString);
    InstallInlineHook(GetProcAddress(LoadLibraryW(L"ntdll.dll"), "RtlFreeHeap"), MyRtlFreeHeap);
}

void safe_exit() {
    std::wstring path = GetProgramDirectory_utf16() + L"\\SafeMemoryCleaner.exe";
    std::wstring parameters = std::to_wstring(GetCurrentProcessId());

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = path.c_str();
    sei.lpParameters = parameters.c_str();
    sei.nShow = SW_SHOWNORMAL;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;

    if (ShellExecuteExW(&sei) && sei.hProcess) {
        WaitForSingleObject(sei.hProcess, INFINITE);
        CloseHandle(sei.hProcess);
        MessageBoxW(0, L"SafeMemoryCleaner�����ڲ�����δ��������������", L"����", 0);
    }
    else {
        MessageBoxW(0, L"SafeMemoryCleanerδ��������������·����Ȩ��", L"����", 0);
    }
}
