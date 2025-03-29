#include "memsafe.h"
#include "config.h"

void secure_erase_string(std::string& str) {
    if (!str.empty()) {
        memset(&str[0], 0, str.size());
        str.clear();
        str.shrink_to_fit();
    }
}

void secure_erase_wstring(std::wstring& wstr) {
    if (!wstr.empty()) {
        memset(&wstr[0], 0, wstr.size() * sizeof(wchar_t));
        wstr.clear();
        wstr.shrink_to_fit();
    }
}

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

PVOID MyRtlDestroyHeap(PVOID HeapHandle) {
    return NULL;
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
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    if (ntdll) {
        void* RtlFreeHeap_ptr = GetProcAddress(ntdll, "RtlFreeHeap");
        if(RtlFreeHeap_ptr) InstallInlineHook(RtlFreeHeap_ptr, MyRtlFreeHeap);
        void* RtlDestroyHeap_ptr = GetProcAddress(ntdll, "RtlDestroyHeap");
        if (RtlDestroyHeap_ptr) InstallInlineHook(RtlDestroyHeap_ptr, MyRtlDestroyHeap);
    }
}

std::wstring GetProgramDirectory_utf16() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring fullPath(exePath);
    std::wstring::size_type pos = fullPath.find_last_of(L"\\/");
    return fullPath.substr(0, pos);
}

void safe_exit() {
    std::wstring path = L"\"" + GetProgramDirectory_utf16() + L"\\SafeMemoryCleaner.exe\"";
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
        MessageBoxW(0, L"SafeMemoryCleaner发生内部错误，未正常结束本程序", L"警告", 0);
    }
    else {
        MessageBoxW(0, L"SafeMemoryCleaner未正常启动，请检查路径及权限", L"警告", 0);
    }
}
