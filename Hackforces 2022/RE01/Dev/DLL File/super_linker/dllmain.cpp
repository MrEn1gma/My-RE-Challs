// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "xorstr.hpp"
#include "aes.c"
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <stdint.h>
#include <string>
#include <winternl.h>
#pragma intrinsic(_ReturnAddress)
#pragma warning(disable : 4996)

static char enc1[] = { 16, 6, 54, 12, 11, 28, 62, 18, 23, 27, 57, 27, 60, 6, 23, 7, 29 }; // cipher of "IsDebuggerPresent"
static char enclib1[] = { 50, 16, 0, 7, 12, 5, 106, 71, 92, 13, 5, 5 };

typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
    IN HANDLE       ProcessHandle,
    IN DWORD        ProcessInformationClass,
    OUT PVOID       ProcessInformation,
    IN ULONG        ProcessInformationLength,
    OUT PULONG      ReturnLength
    );

std::string obfu_func(char inp[]) {
    std::string key = "Yuriii";
    std::string out;
    for (int i = 0; i < strlen(inp); i++) {
        out[i] = inp[i] ^ key[i % key.length()];
    }
    return out;
}

int badboitrap(std::string plainxor) {
    int f = 0;
    HMODULE hkernel32 = GetModuleHandleA("kernel32.dll"); // kernel32.dll
    if (!hkernel32) {
        exit(0);
    }
    FARPROC pIsDebuggerPresent = GetProcAddress(hkernel32, plainxor.c_str()); // IsDebuggerPresent
    if (!pIsDebuggerPresent()) {
        f = 1;
    }
    return f;
}

int checkFlag(uint8_t inp[], uint8_t AESCipher[], uint8_t AESKey[], uint8_t AESIv[], uint8_t keyXorCipher[], uint8_t fakef[]) {
    if (!badboitrap(obfu_func(enc1))) {
        ExitProcess(-1);
    }
    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, AESKey, AESIv);
    AES_CBC_encrypt_buffer(&ctx, inp, 64);

    for (int i = 0; i < strlen((char*)AESCipher); i++) {
        inp[i] ^= keyXorCipher[i % strlen((char*)keyXorCipher)];
        //printf("0x%x ", inp[i]);
    }

    if (!memcmp((char*)AESCipher, (char*)inp, strlen((char*)AESCipher))) {
        printf(xorstr_("\nCorrect !!!"));
        exit(0);
    }
    else {
        printf(xorstr_("\nWrong !!!"));
        exit(0);
    }
}

int hackforces() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll) {
        auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (pfnNtQueryInformationProcess) {
            DWORD dwreturned;
            HANDLE hProcessDebugObject = 0;
            const DWORD ProcessDebugObjetHandle = 0x1e;
            NTSTATUS status = pfnNtQueryInformationProcess(GetCurrentProcess(),
                ProcessDebugObjetHandle,
                &hProcessDebugObject,
                sizeof(HANDLE),
                &dwreturned);
            if (NT_SUCCESS(status) && (0 != hProcessDebugObject)) {
                ExitProcess(-1);
                //printf("Detected!!!");
            }
        }
    }
    uint8_t key_[] = { 172, 195, 87, 162, 90, 34, 56, 190, 116, 30, 56, 39, 178, 152, 180, 162 };
    uint8_t fakeflag[] = { 72, 97, 99, 107, 102, 111, 114, 99, 101, 115, 123, 87, 114, 48, 110, 103, 95, 52, 110, 115, 119, 51, 114, 95, 33, 33, 33, 95, 83, 108, 97, 112, 45, 115, 108, 97, 112, 45, 115, 108, 97, 112, 95, 48, 102, 57, 55, 49, 50, 52, 102, 125 };
    uint8_t iv_[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    uint8_t cipher_[] = { 20, 213, 68, 180, 24, 42, 157, 37, 64, 77, 7, 207, 54, 12, 45, 89, 15, 27, 150, 96, 45, 27, 175, 38, 188, 247, 66, 99, 123, 106, 66, 62, 60, 180, 96, 253, 2, 57, 92, 10, 132, 192, 165, 139, 20, 110, 191, 169, 158, 195, 222, 93, 90, 45, 52, 178, 49, 240, 221, 119, 42, 167, 89, 218 };
    uint8_t keyxor_[] = { 55, 149, 172, 107, 34, 65, 179, 64, 172, 84, 90, 168, 155, 86, 44, 61, 116, 166, 109, 136, 90, 56, 86, 51, 106, 88, 95, 182, 9, 135, 99, 197, 48, 80, 3, 122, 186, 168, 176, 164, 20, 136, 197, 3, 103, 42, 154, 140, 100, 164, 163, 4, 78, 179, 45, 129, 136, 112, 112, 95, 197, 53, 144, 38 };
    uint8_t yourInput[256];
    memset(yourInput, 0, 256);
    printf(xorstr_("FLAG: "));
    scanf("%64s", &yourInput);
    checkFlag(yourInput, cipher_, key_, iv_, keyxor_, fakeflag);
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hackforces();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

