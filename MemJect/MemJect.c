#include <stdint.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>  
#include <stdlib.h>  


// Target process name
#define PROCESS_NAME "csgo.exe"

#define ERASE_ENTRY_POINT 1
#define ERASE_PE_HEADER 1

#define JUNKS \
__asm _emit 0x0a \
__asm _emit 0x0c \
__asm _emit 0x0b \
__asm _emit 0x0d \
__asm _emit 0x01 \
__asm _emit 0x03 \
__asm _emit 0x05 \
__asm _emit 0x07 \
__asm _emit 0x09 \

// Don't change this!
#define _JUNK_BLOCK(s) __asm jmp s JUNKS __asm s:

#pragma warning(disable : 4996)


typedef struct {
    PBYTE imageBase;
    HMODULE(WINAPI* loadLibraryA)(PCSTR);
    FARPROC(WINAPI* getProcAddress)(HMODULE, PCSTR);
    VOID(WINAPI* rtlZeroMemory)(PVOID, SIZE_T);
} LoaderData;

DWORD WINAPI loadLibrary(LoaderData* loaderData)
{
	_JUNK_BLOCK(rando_jmplb1)
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(loaderData->imageBase + ((PIMAGE_DOS_HEADER)loaderData->imageBase)->e_lfanew);
	_JUNK_BLOCK(rando_jmplb2)
    PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(loaderData->imageBase
        + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	_JUNK_BLOCK(rando_jmplb3)
    DWORD delta = (DWORD)(loaderData->imageBase - ntHeaders->OptionalHeader.ImageBase);
	_JUNK_BLOCK(rando_jmplb4)
	while (relocation->VirtualAddress) {
		PWORD relocationInfo = (PWORD)(relocation + 1);
		_JUNK_BLOCK(rando_jmplb5)
        for (int i = 0, count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i < count; i++) {
			_JUNK_BLOCK(rando_jmplb6)
			if (relocationInfo[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
			{
				_JUNK_BLOCK(rando_jmplb7)
				*(PDWORD)(loaderData->imageBase + (relocation->VirtualAddress + (relocationInfo[i] & 0xFFF))) += delta;
			}
		}
		_JUNK_BLOCK(rando_jmplb8)
        relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);
    }

	_JUNK_BLOCK(rando_jmplb9)
    PIMAGE_IMPORT_DESCRIPTOR importDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(loaderData->imageBase
        + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	_JUNK_BLOCK(rando_jmplb10)
    while (importDirectory->Characteristics) {
		_JUNK_BLOCK(rando_jmplb11)
        PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDirectory->OriginalFirstThunk);
		_JUNK_BLOCK(rando_jmplb12)
		PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDirectory->FirstThunk);

		_JUNK_BLOCK(rando_jmplb13)
        HMODULE module = loaderData->loadLibraryA((LPCSTR)loaderData->imageBase + importDirectory->Name);

		_JUNK_BLOCK(rando_jmplb14)
        if (!module)
            return FALSE;

		_JUNK_BLOCK(rando_jmplb15)
        while (originalFirstThunk->u1.AddressOfData) {
			_JUNK_BLOCK(rando_jmplb16)
            DWORD Function = (DWORD)loaderData->getProcAddress(module, originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG ? (LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF) : ((PIMAGE_IMPORT_BY_NAME)((LPBYTE)loaderData->imageBase + originalFirstThunk->u1.AddressOfData))->Name);

			_JUNK_BLOCK(rando_jmplb17)
            if (!Function)
                return FALSE;

			_JUNK_BLOCK(rando_jmplb18)
            firstThunk->u1.Function = Function;
			_JUNK_BLOCK(rando_jmplb19)
			originalFirstThunk++;
			_JUNK_BLOCK(rando_jmplb20)
            firstThunk++;
        }
		_JUNK_BLOCK(rando_jmplb21)
        importDirectory++;
    }
	_JUNK_BLOCK(rando_jmplb22)
    if (ntHeaders->OptionalHeader.AddressOfEntryPoint) {
		_JUNK_BLOCK(rando_jmplb23)
        DWORD result = ((DWORD(__stdcall*)(HMODULE, DWORD, LPVOID))
            (loaderData->imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint))
            ((HMODULE)loaderData->imageBase, DLL_PROCESS_ATTACH, NULL);

#if ERASE_ENTRY_POINT
		_JUNK_BLOCK(rando_jmplb24)
        loaderData->rtlZeroMemory(loaderData->imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint, 32);
#endif

#if ERASE_PE_HEADER
		_JUNK_BLOCK(rando_jmplb25)
        loaderData->rtlZeroMemory(loaderData->imageBase, ntHeaders->OptionalHeader.SizeOfHeaders);
#endif
		_JUNK_BLOCK(rando_jmplb26)
        return result;
    }
    return TRUE;
}

VOID stub(VOID) { }

VOID decryptBinary(uint8_t* binary, PCSTR key)
{
	SIZE_T keyLenth = strlen(key);

	for (int i = 0; i < sizeof(binary); i++)
		binary[i] ^= key[i % keyLenth];
}

uint8_t* readFileBytes(const char* name)
{
	FILE* fl = fopen(name, "rb");
	if (fl == NULL) {
		return 0;
	}
	fseek(fl, 0, SEEK_END);
	long len = ftell(fl);
	fseek(fl, 0, SEEK_SET);
	uint8_t* ret = malloc(len);
	fread(ret, 1, len, fl);
	fclose(fl);
	return ret;
}

INT main(INT argc, PCSTR* argv)
{
	if (argc == 1) {
		printf("usage: %s <path-to-dll> [-key xor-key-to-decrypt-dll]", argv[0]);
		exit(1);
	}

	char* errStr = NULL;

	uint8_t* binary = readFileBytes(argv[1]);
	if (binary == 0) {
		const char* errStrPartial = "failed to open ";
		long length = strlen(errStrPartial) + strlen(argv[1]);
		errStr = malloc(length);
		memset(errStr, 0, length);
		strcat(errStr, errStrPartial);
		strcat(errStr, argv[1]);
		perror(errStr);
		exit(1);
	}

	if (argc > 3 && !strcmp(argv[2], "-key")) {
		decryptBinary(binary, argv[3]);
	}

    HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processSnapshot == INVALID_HANDLE_VALUE)
        return 1;

    HANDLE process = NULL;
    PROCESSENTRY32 processInfo = { sizeof(processInfo) };

    if (Process32First(processSnapshot, &processInfo)) {
        while (Process32Next(processSnapshot, &processInfo)) {
            if (!strcmp(processInfo.szExeFile, PROCESS_NAME)) {
                process = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, processInfo.th32ProcessID);
				break;
            }
        }
    }

	CloseHandle(processSnapshot);

    if (!process) {
		printf("%s is not running", PROCESS_NAME);
        return 1;
    }


    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)binary;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(binary + dosHeader->e_lfanew);

    PBYTE executableImage = VirtualAllocEx(process, NULL, ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    WriteProcessMemory(process, executableImage, binary,
        ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
        WriteProcessMemory(process, executableImage + sectionHeaders[i].VirtualAddress,
        binary + sectionHeaders[i].PointerToRawData, sectionHeaders[i].SizeOfRawData, NULL);

    LoaderData* loaderMemory = (LoaderData*)VirtualAllocEx(process, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READ);

    LoaderData loaderParams = { executableImage, LoadLibraryA, GetProcAddress, (VOID(WINAPI*)(PVOID, SIZE_T))GetProcAddress(GetModuleHandleW(L"ntdll"), "RtlZeroMemory") };

    WriteProcessMemory(process, loaderMemory, &loaderParams, sizeof(LoaderData),
        NULL);
    WriteProcessMemory(process, loaderMemory + 1, loadLibrary,
        (DWORD)stub - (DWORD)loadLibrary, NULL);
    WaitForSingleObject(CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)(loaderMemory + 1),
        loaderMemory, 0, NULL), INFINITE);
	VirtualFreeEx(process, loaderMemory, 0, MEM_RELEASE);

	free(binary);
}

