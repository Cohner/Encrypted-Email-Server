#ifndef CLIENT_TOOLS_H
#define CLIENT_TOOLS_H
#include <gcrypt.h>
#include <rsa.h>
#include <cryptlib.h>
#include <secblock.h>
#include <string>

namespace clientTools_h
{
    void GcryInit();
    std::string KeyGen();
    
    void SavePrivateKey(const std::string&, const CryptoPP::RSA::PrivateKey&);
    void SavePublicKey(std::string*, const CryptoPP::RSA::PublicKey&);
    void Save(const std::string&, const CryptoPP::BufferedTransformation&);
    void StringSave(std::string*, const CryptoPP::BufferedTransformation&);
    
    void LoadPrivateKey(const std::string&, CryptoPP::RSA::PrivateKey&);
    void LoadPublicKey(std::string*, CryptoPP::RSA::PublicKey&);
    void Load(const std::string&, CryptoPP::BufferedTransformation&);
    void StringLoad(std::string*, CryptoPP::BufferedTransformation&);
    
    std::string Encrypt(CryptoPP::RSA::PublicKey&, std::string);
    std::string Decrypt(CryptoPP::RSA::PrivateKey&, std::string);
}

#endif