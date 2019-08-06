#include <stdint.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>  


// Target process name
#define PROCESS_NAME "csgo.exe"

#define ERASE_ENTRY_POINT 1
#define ERASE_PE_HEADER 1

#pragma warning(disable: 4996)


typedef struct {
	PBYTE imageBase;
	HMODULE(WINAPI* loadLibraryA)(PCSTR);
	FARPROC(WINAPI* getProcAddress)(HMODULE, PCSTR);
	VOID(WINAPI* rtlZeroMemory)(PVOID, SIZE_T);
} LoaderData;

DWORD WINAPI shellcode(LoaderData* loaderData)
{
	PBYTE pBase = loaderData->imageBase;

	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(pBase + ((PIMAGE_DOS_HEADER)pBase)->e_lfanew);
	IMAGE_OPTIONAL_HEADER optHeader = ntHeader->OptionalHeader;

	// delta between the actual addressand the desired address 
	DWORD deltaAddr = (DWORD)(pBase - optHeader.ImageBase);

	// get the first relocation block
	PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(pBase + optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	while (relocation->VirtualAddress) {
		PWORD relocationInfo = (PWORD)(relocation + 1);
		UINT numOfEntries = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		for (UINT i = 0; i < numOfEntries; i++)
		{
			// the high 4 bits of relocationInfo are the type of the relocation
			// the low 12 bits are a relocation offset, need to be added to the VirtualAddress of this relocation block.
			if (relocationInfo[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
				* (PDWORD)(pBase + (relocation->VirtualAddress + (relocationInfo[i] & 0xFFF))) += deltaAddr;
		}

		// go to the next relocation block
		relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);
	}

	// wire all the imports
	PIMAGE_IMPORT_DESCRIPTOR importDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	while (importDirectory->Characteristics) {
		HMODULE module = loaderData->loadLibraryA((LPCSTR)pBase + importDirectory->Name);

		if (!module) return FALSE;

		PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)(pBase + importDirectory->OriginalFirstThunk);
		PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(pBase + importDirectory->FirstThunk);

		while (originalFirstThunk->u1.AddressOfData) {
			DWORD Function = (DWORD)loaderData->getProcAddress(
				module,
				// getProcAddress can either load the function by its ordinal number or by its name,
				// it needs to be determined based on how compiler genrated the code
				originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG ?
				(LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF) :
				((PIMAGE_IMPORT_BY_NAME)((LPBYTE)pBase + originalFirstThunk->u1.AddressOfData))->Name
			);

			if (!Function)
				return FALSE;

			firstThunk->u1.Function = Function;
			originalFirstThunk++;
			firstThunk++;
		}
		importDirectory++;
	}

	// execute tls callbacks
	PIMAGE_TLS_DIRECTORY tlsDirectory = (PIMAGE_TLS_DIRECTORY)(pBase + optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
	PIMAGE_TLS_CALLBACK* tlsCallback = (PIMAGE_TLS_CALLBACK*)(tlsDirectory->AddressOfCallBacks);
	while (*tlsCallback) {
		(*tlsCallback)(pBase, DLL_PROCESS_ATTACH, NULL);
		tlsCallback++;
	}

	// call dllmain
	if (optHeader.AddressOfEntryPoint) {
		DWORD result = ((DWORD(__stdcall*)(HMODULE, DWORD, LPVOID))
			(pBase + optHeader.AddressOfEntryPoint))
			((HMODULE)pBase, DLL_PROCESS_ATTACH, NULL);

#if ERASE_ENTRY_POINT
		loaderData->rtlZeroMemory(pBase + optHeader.AddressOfEntryPoint, 32);
#endif

#if ERASE_PE_HEADER
		loaderData->rtlZeroMemory(pBase, optHeader.SizeOfHeaders);
#endif
		return result;
	}
	return TRUE;
}

VOID stub(VOID) { }

uint8_t* readFileBytes(const char* name)
{
	FILE* fl = fopen(name, "rb");
	if (!fl) return 0;

	fseek(fl, 0, SEEK_END);
	long len = ftell(fl);
	fseek(fl, 0, SEEK_SET);
	uint8_t* ret = malloc(len);
	if (!ret) return 0;

	fread(ret, 1, len, fl);
	fclose(fl);
	return ret;
}

INT main(INT argc, PCSTR* argv)
{
	printf("size of shellcode: %lu bytes\n", (DWORD)((DWORD)stub - (DWORD)shellcode));
	if (argc == 1) {
		printf("usage: %s <path-to-dll> [-key xor-key-to-decrypt-dll]", argv[0]);
		exit(1);
	}

	uint8_t* binary = readFileBytes(argv[1]);
	if (binary == 0) {
		fprintf(stderr, "failed to open %s: %s\n", argv[1], strerror(errno));
		exit(1);
	}

	HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (processSnapshot == INVALID_HANDLE_VALUE) return 1;

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

	PBYTE executableImage = VirtualAllocEx(process, NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(process, executableImage, binary, ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

	PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
		WriteProcessMemory(process, executableImage + sectionHeaders[i].VirtualAddress,
			binary + sectionHeaders[i].PointerToRawData, sectionHeaders[i].SizeOfRawData, NULL);
	free(binary);

	LoaderData* loaderMemory = (LoaderData*)VirtualAllocEx(process, NULL, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
	LoaderData loaderParams = { executableImage, LoadLibraryA, GetProcAddress, (VOID(WINAPI*)(PVOID, SIZE_T))GetProcAddress(GetModuleHandleW(L"ntdll"), "RtlZeroMemory") };
	WriteProcessMemory(process, loaderMemory, &loaderParams, sizeof(LoaderData), NULL);
	WriteProcessMemory(process, loaderMemory + 1, shellcode, (DWORD)stub - (DWORD)shellcode, NULL);

	WaitForSingleObject(CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)(loaderMemory + 1), loaderMemory, 0, NULL), INFINITE);
	VirtualFreeEx(process, loaderMemory, 0, MEM_RELEASE);

	printf("%s injected\n", argv[1]);
}
