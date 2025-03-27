#pragma once
#include <string>

bool set_config_int(const std::wstring& key, int value);
int get_config_int(const std::wstring& key, int defaultValue);
std::wstring GetProgramDirectory_utf16();
