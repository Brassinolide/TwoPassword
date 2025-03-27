#include "setting.h"
#include <windows.h>

std::wstring GetProgramDirectory_utf16() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring fullPath(exePath);
    std::wstring::size_type pos = fullPath.find_last_of(L"\\/");
    return fullPath.substr(0, pos);
}

bool set_config_int(const std::wstring& key, int value) {
    std::wstring iniFilePath = GetProgramDirectory_utf16() + L"\\setting.ini";

    wchar_t buffer[32];
    _itow_s(value, buffer, 32, 10);

    return  (WritePrivateProfileStringW(L"TwoPassword", key.c_str(), buffer, iniFilePath.c_str()) != FALSE);
}

int get_config_int(const std::wstring& key, int defaultValue) {
    std::wstring iniFilePath = GetProgramDirectory_utf16() + L"\\setting.ini";

    return static_cast<int>(GetPrivateProfileIntW(L"TwoPassword", key.c_str(), defaultValue, iniFilePath.c_str()));
}
