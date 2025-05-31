#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

int main() {
    const char* server_ip = "127.0.0.1"; // Change if needed
    const int server_port = 8080;        // Change to match your server

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        std::cerr << "Socket creation failed.\n";
        return 1;
    }

    // Server address
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

    // Connect to server
    if (connect(sock, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Connection to server failed.\n";
        close(sock);
        return 1;
    }

    std::cout << "Connected to server.\n";

    // Send request (JSON or raw message your server expects)
    std::string message = R"({"req": "newUser", "name": "Ashray", "password": "iiita123", "email": "a@gmail.com"})";
    send(sock, message.c_str(), message.size(), 0);

    // Receive response
    char buffer[4096] = {0};
    int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived > 0) {
        std::cout << "Server response: " << buffer << "\n";
    } else {
        std::cerr << "No response from server.\n";
    }

    // Close socket
    close(sock);
    return 0;
}
