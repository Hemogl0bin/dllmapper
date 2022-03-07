#include "mapper.h"
#include "utils.h"

int main(int argc, const char **argv)
{
    if(argc != 3)
    {
        utils::LogError("Invalid syntax, please use: dllmapper.exe [process name] [dll path]");
        return 0;
    }

    unsigned char *dllBuffer = utils::LoadFileFromDisk(argv[2]);
    if(mapper::MapDLL(argv[1], dllBuffer))
    {
        utils::LogInfo("Injection succeeded");
    }
    else
    {
        utils::LogError("Injection failed");
    }

    VirtualFree(dllBuffer, 0, MEM_RELEASE);

    system("pause");
    return 0;
}