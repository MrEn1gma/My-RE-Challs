// re_01.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include "resource.h"

int main()
{
    printf("----------------=================[ RE01 ]=================----------------\n");
    printf("|[INFO] Good luck and have fun ;)                                        |\n");
    printf("----------------=================[ RE01 ]=================----------------\n");
    HRSRC shellcodeResource = FindResource(NULL, MAKEINTRESOURCE(IDR_HACKFORCES_20221), L"Hackforces_2022");
    DWORD shellcodeSize = SizeofResource(NULL, shellcodeResource);
    HGLOBAL shellcodeResourceData = LoadResource(NULL, shellcodeResource);

    void* exec = VirtualAlloc(0, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, shellcodeResourceData, shellcodeSize);
    ((void(*)())exec)();
    return 0;
}