#ifndef DATABASE_H
#define DATABASE_H
#include <string>
#include <vector>
#include <gcrypt.h>
#include "packet.pb.h"
namespace database_h
{
    static int callback(void*, int, char**, char**);
    int TestCode();
    int CreateDatabase();
    int FindUser(std::string);
    void CreateUser(std::string, std::string, std::string, std::string);
    std::vector<std::string> GetPassword(std::string);
    void WriteMessage(std::string, std::string, std::string, std::string);
    void GetMessages(packet::Packet*, std::string);
    std::vector<std::string> GetPublicKey(std::string);
    std::vector<std::string> GetAllUsers();
}

#endif