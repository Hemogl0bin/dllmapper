# dllmapper
Manually map DLLs into a specified process

## Usage
The syntax for the program is: ```dllmapper.exe [process name] [dll path]```. For unloading your dll you cannot use ```FreeLibraryAndExitThread()``` and instead must use ```VirtualFree()```.

## Disclaimer
As of now, this program only works for x64 processes and DLLs.