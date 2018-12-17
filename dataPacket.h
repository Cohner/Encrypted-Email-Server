#ifndef PACKET_H
#define PACKET_H
#include <string>
#include <vector>
#include <time.h>

namespace dataPacket
{
    struct data{
        int option;
        const char* salt[3072];
        const char* username[3072];
        const char* password[3072];
        const char* publicKey[3072];
        std::vector<std::string> recipient;
        std::vector<std::string> subject;
        std::vector<std::string> message;
        time_t date;
        std::vector<std::string> all_users;
        const char* errorMessage;
    };
}

#endif