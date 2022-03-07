#pragma once
#include <Windows.h>

#include <string>

namespace utils
{
    DWORD GetProcessId(std::string processName);
    unsigned char* LoadFileFromDisk(const std::string& dllPath);

    void LogInfo(const std::string &message);
    void LogError(const std::string &message);
}