// Sample.cpp

#include "clientTools.h"

#include <rsa.h>
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include <sha.h>
using CryptoPP::SHA1;

#include <filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include <files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <secblock.h>
using CryptoPP::SecByteBlock;

#include <cryptlib.h>
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include <string>
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <assert.h>

#include "packet.pb.h"

#include "database.h"



int main(int argc, char* argv[])
{
    try
    {
        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize( rng, 3072 );

        RSA::PrivateKey privateKey( parameters );
        RSA::PrivateKey testLoadKey;
        RSA::PublicKey publicKey( parameters );
        string testSaveKey;
        
        clientTools_h::SavePublicKey(&testSaveKey, publicKey);
        clientTools_h::LoadPublicKey(&testSaveKey, publicKey);

        string plain="Oh my god, it's that easy", cipher, recovered;

        ////////////////////////////////////////////////
        // Encryption
        cipher = clientTools_h::Encrypt(publicKey, plain);
        
        clientTools_h::SavePrivateKey("nothingSecretHere", privateKey);
        clientTools_h::LoadPrivateKey("nothingSecretHere", testLoadKey);
        
        cout << testSaveKey << endl;
        ////////////////////////////////////////////////
        ////////////////////////////////////////////////

        ////////////////////////////////////////////////
        // Decryption
        recovered = clientTools_h::Decrypt(privateKey, cipher);

        assert( plain == recovered );
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }
    
    
    string user = "Joey";
    string password = "badpassword";
    string salt = "SeaSalt";
    string key = "somekey";
    string hash = bcrypt.generateHash(password.append(salt));
    
    string enteredPassword = "badpassword";
    if(database_h::FindUser(user)){
        cout << "Joey already exists" << endl;
    }else{
        database_h::CreateUser(user, hash, salt, key);
    }
    
    if(database_h::FindUser(user)){
        vector<string> joeyPass = database_h::GetPassword(user);
        cout << bcrypt.validatePassword(enteredPassword.append(joeyPass.at(1)),joeyPass.at(0)) << endl;
    }else{
        cout << "User not found in database" << endl;
    }
    
    if(database_h::FindUser(user)){
        vector<string> joeyKey = database_h::GetPublicKey(user);
        cout << joeyKey.at(0) << endl;
    }else{
        cout << "User not found in database" << endl;
    }

	return 0;
}

