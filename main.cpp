#include <iostream>
#include <random>
#include <unordered_map>
#include <cstring>
#include <stdexcept>

// SQL Headers
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <cppconn/exception.h>
#include <cppconn/prepared_statement.h>


//TCP connection headers
#include <thread>
#include <vector>
#include <mutex>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>

//handle Json
#include "json.hpp"
using json = nlohmann::json;

// for password hashing
#include "includes/bcrypt.h"

//global constants for running sql statements
sql::mysql::MySQL_Driver* driver;
std::unique_ptr<sql::Connection> con;

//for message forwarding
std::unordered_map<std::string,int> onlineClients;
std::mutex clientMutex;

// Generate a random session key
std::string generateRandomKey(int length = 32) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    std::string key;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(alphanum) - 2);

    for (int i = 0; i < length; ++i)
        key += alphanum[dis(gen)];

    return key;
}

//encryption and de-encryption of password
std::string hashPassword(std::string password){
    std::string hash = bcrypt::generateHash(password);
    return hash;
}


bool matchPassword(std::string input,std::string hash){
    bool match = bcrypt::validatePassword(input,hash);
    return match;
}




// Set a user online
void setOnline(const json& j, bool isLogin,int clientSocket) {
    try {
        std::string key = generateRandomKey();
        
        if (isLogin) {
            std::unique_ptr<sql::PreparedStatement> pstmt(
                con->prepareStatement("UPDATE user SET isOnline = true, sessionkey = ? WHERE email = ?")
            );
            pstmt->setString(1, key);
            pstmt->setString(2, (std::string)j["email"]);
            pstmt->execute();
            std::lock_guard<std::mutex> lock(clientMutex);
            onlineClients[(std::string)j["email"]] = clientSocket;
        } else {
            std::unique_ptr<sql::PreparedStatement> pstmt(
                con->prepareStatement("SELECT password FROM user WHERE email = ?")
            );
            pstmt->setString(1, (std::string)j["email"]);
            std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
            
            if (res->next()) {
                if (matchPassword(j["password"],res->getString("password"))) {
                    std::unique_ptr<sql::PreparedStatement> updateStmt(
                        con->prepareStatement("UPDATE user SET isOnline = true, sessionkey = ? WHERE email = ?")
                    );
                    updateStmt->setString(1, key);
                    updateStmt->setString(2, (std::string)j["email"]);
                    updateStmt->execute();
                    std::lock_guard<std::mutex> lock(clientMutex);
                    onlineClients[(std::string)j["email"]] = clientSocket;
                } else {
                    std::cerr << "Incorrect password" << std::endl;
                }
            } else {
                std::cerr << "User not found" << std::endl;
            }
        }
    } catch (const sql::SQLException& e) {
        std::cerr << "SQL Error in setOnline: " << e.what() << std::endl;
    }
}



// Create a new user and set online with session key
void createNewUser(const json& j,int clientSocket) {
    try {
        std::unique_ptr<sql::PreparedStatement> pstmt(
            con->prepareStatement("INSERT INTO user(email, name, password, isOnline) VALUES (?, ?, ?, ?)")
        );
        std::string hash = hashPassword(j["password"]);
        pstmt->setString(1, (std::string)j["email"]);
        pstmt->setString(2, (std::string)j["name"]);
        pstmt->setString(3, hash);
        pstmt->setBoolean(4, false);
        pstmt->execute();

        setOnline(j, true, clientSocket);
    } catch (const sql::SQLException& e) {
        std::cerr << "SQL Error in createNewUser: " << e.what() << std::endl;
    }
}

// Set a user offline, optionally delete session
void setOffline(const json& j) {
    try {
        bool deleteSession = j["deleteSession"];
        std::string key = j["key"];
        
        std::unique_ptr<sql::PreparedStatement> pstmt(
            con->prepareStatement("SELECT sessionKey FROM user WHERE email = ?")
        );
        pstmt->setString(1, (std::string)j["email"]);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        
        if (res->next()) {
            if (key == res->getString("sessionKey")) {
                if (deleteSession) {
                    std::unique_ptr<sql::PreparedStatement> updateStmt(
                        con->prepareStatement("UPDATE user SET isOnline = false, sessionKey = NULL WHERE email = ?")
                    );
                    updateStmt->setString(1, (std::string)j["email"]);
                    updateStmt->execute();
                } else {
                    std::unique_ptr<sql::PreparedStatement> updateStmt(
                        con->prepareStatement("UPDATE user SET isOnline = false WHERE email = ?")
                    );
                    updateStmt->setString(1, (std::string)j["email"]);
                    updateStmt->execute();
                }
                
                std::lock_guard<std::mutex> lock(clientMutex);
                onlineClients.erase((std::string)j["email"]);
            } else {
                std::cerr << "Invalid session key" << std::endl;
            }
        } else {
            std::cerr << "User not found" << std::endl;
        }
    } catch (const sql::SQLException& e) {
        std::cerr << "SQL Error in setOffline: " << e.what() << std::endl;
    }
}


void createNewCall(json &j,int clientSocket){
    std::string from = j["from"];
    std::string to = j["to"];

    std::lock_guard<std::mutex> lock(clientMutex);
    if (onlineClients.find(to) != onlineClients.end()) {
        int targetSocket = onlineClients[to];

        std::string msg = j.dump();
        send(targetSocket, msg.c_str(), msg.size(), 0);
    } else {
        json err;
        err["resp"] = "userOffline";
        std::string resp = err.dump();
        send(clientSocket, resp.c_str(), resp.size(), 0);
    }
}


void acceptCall(json &j){

}

void rejectCall(json &j){

}

void forgotPassword(json &j){

}

//main logic for handing calls
void handleMessage(const std::string& message,int clientSocket) {
    try {
        json j = json::parse(message);

        std::string reqType = j["req"];
        if (reqType == "newUser") {
            createNewUser(j,clientSocket);
        } else if (reqType == "forgotPassword") {
            forgotPassword(j);
        } else if (reqType == "setUserOnline") {
            setOnline(j,false,clientSocket);
        } else if (reqType == "setUserOffline") {
            setOffline(j);
        } else if (reqType == "makeCall") {
            createNewCall(j,clientSocket);
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
            std::lock_guard<std::mutex> coutLock(coutMutex);
            std::lock_guard<std::mutex> clientLock(clientMutex);
            for(auto &it : onlineClients){
               if(it.second == clientSocket){
                    onlineClients.erase(it.first);
                    break;
                } 
            }
            std::cout << "Client disconnected\n";
            close(clientSocket);
            break;
        }

        buffer[valread] = '\0';
        handleMessage(buffer,clientSocket);
    }
}



int main() {
    try {
        // init of sql connection
        driver = sql::mysql::get_mysql_driver_instance();

        con.reset(driver->connect("tcp://127.0.0.1:3306", "root", "root"));

        con->setSchema("callconnect");

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
