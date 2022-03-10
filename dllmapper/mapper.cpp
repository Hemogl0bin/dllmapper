#include "utils.h"
#include "mapper.h"

using DllMain_t = BOOL(__stdcall*)(HINSTANCE, DWORD, LPVOID);

using LoadLibraryA_t = HMODULE(__stdcall*)(LPCSTR);
using GetProcAddress_t = FARPROC(__stdcall*)(HMODULE, LPCSTR);


constexpr DWORD STATUS_UNKNOWN_ERROR            = -1;
constexpr DWORD STATUS_SUCCESS                  = 0;
constexpr DWORD STATUS_ERROR_LOADING_MODULE     = 1;
constexpr DWORD STATUS_ERROR_LOADING_IMPORT     = 2;
constexpr DWORD STATUS_COMPLETE_NO_ENTRY        = 3;
constexpr DWORD STATUS_COMPLETE_ENTRY_FAILED    = 4;

using ImageFixData = struct _ImageLoadData
{
    unsigned char *imageBase;

    LoadLibraryA_t LoadLibraryA_f;
    GetProcAddress_t GetProcAddress_f;

    DWORD exitCode;
};

void FixImage(ImageFixData *imageFixData)
{
    IMAGE_DOS_HEADER *dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(imageFixData->imageBase);
    IMAGE_NT_HEADERS *ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(imageFixData->imageBase + dosHeader->e_lfanew);

    size_t relocationDelta = reinterpret_cast<size_t>(imageFixData->imageBase - ntHeader->OptionalHeader.ImageBase);
    IMAGE_BASE_RELOCATION *imageBaseRelocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(imageFixData->imageBase + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    /*
    * Relocations
    */
    for(; reinterpret_cast<unsigned char*>(imageBaseRelocation) < reinterpret_cast<unsigned char*>(imageBaseRelocation) + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
        ; *reinterpret_cast<unsigned char**>(&imageBaseRelocation) += imageBaseRelocation->SizeOfBlock)
    {
        int numRelocations = (imageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *typeOffset = reinterpret_cast<WORD*>(imageBaseRelocation + 1);
        for(int i = 0; i < numRelocations; i++)
        {
            size_t *relocation = reinterpret_cast<size_t*>(imageFixData->imageBase + imageBaseRelocation->VirtualAddress + (typeOffset[i] & 0xFFF)); //Take the lower 12 bits of typeOffset
            *relocation += relocationDelta;
        }
    }

    /*
    * Imports
    */
    IMAGE_IMPORT_DESCRIPTOR *importDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(imageFixData->imageBase + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for(int i = 0; importDescriptor[i].Characteristics != 0; i++)
    {
        HMODULE importModule = imageFixData->LoadLibraryA_f(reinterpret_cast<char*>(imageFixData->imageBase + importDescriptor[i].Name));
        if(!importModule)
        {
            imageFixData->exitCode = STATUS_ERROR_LOADING_MODULE;
            return;
        }

        IMAGE_THUNK_DATA *firstThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(imageFixData->imageBase + importDescriptor[i].FirstThunk);
        IMAGE_THUNK_DATA *originalFirstThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(imageFixData->imageBase + importDescriptor[i].OriginalFirstThunk);

        for(int j = 0; originalFirstThunk[j].u1.AddressOfData != 0; j++)
        {
            void *functionLocation = 0;
            if(originalFirstThunk[j].u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                functionLocation = reinterpret_cast<void*>(imageFixData->GetProcAddress_f(importModule, reinterpret_cast<char*>(originalFirstThunk[j].u1.Ordinal & 0xFFFF)));
            }
            else
            {
                IMAGE_IMPORT_BY_NAME *importedFunc = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(imageFixData->imageBase + originalFirstThunk[j].u1.AddressOfData);
                functionLocation = reinterpret_cast<void*>(imageFixData->GetProcAddress_f(importModule, importedFunc->Name));
            }

            if (!functionLocation)
            {
                imageFixData->exitCode = STATUS_ERROR_LOADING_IMPORT;
                return;
            }

            firstThunk[j].u1.Function = reinterpret_cast<ULONGLONG>(functionLocation);
        }
    }

    /*
    * TLS Callbacks
    */
    if(ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
    {
        IMAGE_TLS_DIRECTORY *tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(imageFixData->imageBase + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        PIMAGE_TLS_CALLBACK *callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
        for(int i = 0; callbacks[i] != nullptr; i++)
        {
            callbacks[i](imageFixData->imageBase, DLL_PROCESS_ATTACH, nullptr);
        }
    }

    /*
    * DllMain
    */
    if(ntHeader->OptionalHeader.AddressOfEntryPoint)
    {
        DllMain_t DllMain_f = reinterpret_cast<DllMain_t>(imageFixData->imageBase + ntHeader->OptionalHeader.AddressOfEntryPoint);
        imageFixData->exitCode = DllMain_f(reinterpret_cast<HINSTANCE>(imageFixData->imageBase), DLL_PROCESS_ATTACH, nullptr) ? STATUS_SUCCESS : STATUS_COMPLETE_ENTRY_FAILED;
    }
    else
    {
        imageFixData->exitCode = STATUS_COMPLETE_NO_ENTRY;
    }
}

bool mapper::MapDLL(const std::string& processName, unsigned char *dllBuffer)
{
    IMAGE_DOS_HEADER *dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(dllBuffer);
    if(dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        utils::LogError("File contains invalid DOS header");
        return false;
    }

    IMAGE_NT_HEADERS *ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(dllBuffer + dosHeader->e_lfanew);
    if(ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        utils::LogError("File contains invalid NT header");
        return false;
    }

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, false, utils::GetProcessId(processName));
    if(!process)
    {
        utils::LogError("Unable to open target process");
        return false;
    }

    unsigned char *remoteImage = reinterpret_cast<unsigned char*>(VirtualAllocEx(process, nullptr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if(!remoteImage)
    {
        CloseHandle(process);
        utils::LogError("Unable to allocate memory for remote image");
        return false;
    }

    size_t bytesTransferred = 0;
    WriteProcessMemory(process, remoteImage, dllBuffer, ntHeader->OptionalHeader.SizeOfHeaders, &bytesTransferred);
    if(bytesTransferred != ntHeader->OptionalHeader.SizeOfHeaders)
    {
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        CloseHandle(process);
        utils::LogError("Failed to write headers to remote memory");
        return false;
    }

    IMAGE_SECTION_HEADER *sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
    for(int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        WriteProcessMemory(process, remoteImage + sectionHeader[i].VirtualAddress, dllBuffer + sectionHeader[i].PointerToRawData, sectionHeader[i].SizeOfRawData, &bytesTransferred);
        if(bytesTransferred != sectionHeader[i].SizeOfRawData)
        {
            VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
            CloseHandle(process);
            utils::LogError("Failed to write section to remote memory");
            return false;
        }
    }

    unsigned char *imageFixBuffer = reinterpret_cast<unsigned char*>(VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if(!imageFixBuffer)
    {
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        CloseHandle(process);
        utils::LogError("Failed to allocate memory for performing relocations and resolving imports");
        return false;
    }

    ImageFixData imageFixData;
    imageFixData.imageBase = remoteImage;
    imageFixData.GetProcAddress_f = GetProcAddress;
    imageFixData.LoadLibraryA_f = LoadLibraryA;
    imageFixData.exitCode = STATUS_UNKNOWN_ERROR;

    WriteProcessMemory(process, imageFixBuffer, &imageFixData, sizeof(ImageFixData), &bytesTransferred);
    if(bytesTransferred != sizeof(ImageFixData))
    {
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        VirtualFreeEx(process, imageFixBuffer, 0, MEM_RELEASE);
        CloseHandle(process);
        utils::LogError("Failed to write image fix data");
        return false;
    }

    WriteProcessMemory(process, imageFixBuffer + sizeof(ImageFixData), FixImage, 0x1000 - sizeof(ImageFixData), &bytesTransferred);
    if(bytesTransferred != 0x1000 - sizeof(ImageFixData))
    {
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        VirtualFreeEx(process, imageFixBuffer, 0, MEM_RELEASE);
        CloseHandle(process);
        utils::LogError("Failed to write image fix shellcode");
        return false;
    }

    HANDLE thread = CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(imageFixBuffer + sizeof(ImageFixData)), imageFixBuffer, 0, nullptr);

    if(!thread)
    {
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        VirtualFreeEx(process, imageFixBuffer, 0, MEM_RELEASE);
        CloseHandle(process);
        utils::LogError("Failed to execute image fix shellcode");
        return false;
    }

    if(WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0)
    {
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        VirtualFreeEx(process, imageFixBuffer, 0, MEM_RELEASE);
        CloseHandle(process);
        utils::LogError("Image fix shellcode did not finish after 10 seconds");
        return false;
    }

    CloseHandle(thread);

    DWORD statusCode = STATUS_UNKNOWN_ERROR;
    if(!ReadProcessMemory(process, imageFixBuffer + FIELD_OFFSET(ImageFixData, exitCode), &statusCode, sizeof(DWORD), &bytesTransferred) || bytesTransferred != sizeof(DWORD))
    {
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        VirtualFreeEx(process, imageFixBuffer, 0, MEM_RELEASE);
        CloseHandle(process);
        utils::LogError("Failed to read status code of image fix shellcode");
        return false;
    }

    switch(statusCode)
    {
    case STATUS_SUCCESS:
        utils::LogInfo("Image mapped successfully");
        break;
    case STATUS_ERROR_LOADING_MODULE:
        utils::LogError("Failed to load a required module");
        break;
    case STATUS_ERROR_LOADING_IMPORT:
        utils::LogError("Failed to resolve an import");
        break;
    case STATUS_COMPLETE_NO_ENTRY:
        utils::LogError("Failed to find target module's entry point");
        break;
    case STATUS_COMPLETE_ENTRY_FAILED:
        utils::LogError("Target module's entry point returned false");
        break;
    default:
        utils::LogError("Unknown error occurred");
    }

    VirtualFreeEx(process, imageFixBuffer, 0, MEM_RELEASE);
    CloseHandle(process);

    return statusCode == STATUS_SUCCESS;
}
