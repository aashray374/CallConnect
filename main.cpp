#include <iostream>

// SQL Headers
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <cppconn/exception.h>

//TCP connection headers
#include <thread>
#include <vector>
#include <mutex>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>

//handle Json
#include <nlohmann/json.hpp> 
using json = nlohmann::json;

//global constants for running sql statements
sql::mysql::MySQL_Driver* driver;
std::unique_ptr<sql::Connection> con;
std::unique_ptr<sql::Statement> stmt;
std::unique_ptr<sql::ResultSet> res;


//main logic for handing calls
void handleMessage(const std::string& message) {
    try {
        json j = json::parse(message);

        std::string reqType = j["req"];
        if (reqType == "newUser") {
            createNewUser(j);
        } else if (reqType == "forgotPassword") {
            forgotPassword(j);
        } else if (reqType == "setUserOnline") {
            setOnline(j);
        } else if (reqType == "setUserOffline") {
            setOffline(j);
        } else if (reqType == "makeCall") {
            createNewCall(j);
        } else if (reqType == "acceptCall") {
            acceptCall(j);
        } else if (reqType == "rejectCall") {
            rejectCall(j);
        } else {
            std::cerr << "Invalid request type" << std::endl;
        }


    } catch (json::parse_error& e) {
        std::cerr << "Invalid JSON: " << e.what() << std::endl;
    }
}

//handle tcp requests
std::mutex coutMutex;
void handleClient(int clientSocket) {
    char buffer[4096] = {0};
    while (true) {
        int valread = read(clientSocket, buffer, 1024);
        if (valread <= 0) {
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cout << "Client disconnected\n";
            close(clientSocket);
            break;
        }

        buffer[valread] = '\0';
        handleMessage(buffer);
    }
}



int main() {
    try {
        // init of sql connection
        driver = sql::mysql::get_mysql_driver_instance();

        con.reset(driver->connect("tcp://127.0.0.1:3306", "root", "root"));

        con->setSchema("callconnect");

        stmt.reset(con->createStatement());

        //init of TCP connection
        int server_fd, new_socket;
        sockaddr_in address;
        int opt = 1;
        int addrlen = sizeof(address);
        const int PORT = 8080;

        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd == 0) {
            perror("socket failed");
            exit(EXIT_FAILURE);
        }

        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(PORT);

        bind(server_fd, (struct sockaddr *)&address, sizeof(address));
        listen(server_fd, 10);

        std::cout << "Server listening on port " << PORT << std::endl;


        //listen for tcp requests continuously
        while (true) {
            new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
            std::cout << "New client connected\n";

            std::thread clientThread(handleClient, new_socket);
            clientThread.detach(); 
        }


    } catch (sql::SQLException &e) {
        std::cerr << "SQL error: " << e.what() << std::endl;
    }

    return 0;
}
