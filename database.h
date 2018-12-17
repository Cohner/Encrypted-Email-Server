#ifndef DATABASE_H
#define DATABASE_H
#include <string>
#include <vector>
#include "packet.pb.h"
namespace database_h
{
    static int callback(void*, int, char**, char**);
    int TestCode();
    int CreateDatabase(std::string);
    int FindUser(std::string, std::string);
    void CreateUser(std::string, std::string, std::string, std::string, std::string);
    std::vector<std::string> GetPassword(std::string, std::string);
    void WriteMessage(std::string, std::string, std::string, std::string, std::string);
    void GetMessages(packet::Packet*, std::string, std::string);
    std::vector<std::string> GetPublicKey(std::string, std::string);
    std::vector<std::string> GetAllUsers(std::string);
}

#endif