#include <Windows.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#undef UNICODE          //Forces Tlhelp32 to use ANSI strings
#include <TlHelp32.h>

#include "utils.h"

DWORD utils::GetProcessId(std::string processName)
{
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(!snapshot)
    {
        return processId;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    if(!Process32First(snapshot, &processEntry))
    {
        CloseHandle(snapshot);
        return processId;
    }

    do
    {
        std::string currProcessName = std::string(processEntry.szExeFile);
        std::transform(currProcessName.begin(), currProcessName.end(), currProcessName.begin(), [](char c){ return std::tolower(c); });
        std::transform(processName.begin(), processName.end(), processName.begin(), [](char c ){ return std::tolower(c); });
        
        if(currProcessName == processName)
        {
            processId = processEntry.th32ProcessID;
            break;
        }
    }
    while(Process32Next(snapshot, &processEntry));

    CloseHandle(snapshot);
    return processId;
}

unsigned char *utils::LoadFileFromDisk(const std::string &dllPath)
{
    std::ifstream dllFile = std::ifstream(dllPath, std::ifstream::binary);
    if(!dllFile.is_open())
    {
        LogError("Unable to open " + dllPath + " for reading");
        return nullptr;
    }

    dllFile.seekg(0, std::ifstream::beg);
    dllFile.seekg(0, std::ifstream::end);
    size_t fileSize = dllFile.tellg();
    dllFile.seekg(0, std::ifstream::beg);

    if(fileSize <= 0)
    {
        dllFile.close();
        LogError("Invalid file " + dllPath);
        return nullptr;
    }

    unsigned char *buffer = reinterpret_cast<unsigned char*>(VirtualAlloc(nullptr, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if(!buffer)
    {
        dllFile.close();
        LogError("Unable to allocate memory for file " + dllPath);
        return nullptr;
    }

    dllFile.read(reinterpret_cast<char*>(buffer), fileSize);

    dllFile.close();
    return buffer;
}

void utils::LogInfo(const std::string &message)
{
    std::cout << "[~] " << message << std::endl;
}

void utils::LogError(const std::string &message)
{
    std::cout << "[!] " << message << std::endl;
}