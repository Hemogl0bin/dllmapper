#pragma once
#include <Windows.h>

#include <string>

namespace mapper
{
    bool MapDLL(const std::string &processName, unsigned char* dllBuffer);
}