// Sample.cpp

#include "clientTools.h"
#include "bcrypt/BCrypt.hpp"

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

#include <unistd.h>

#include <vector>
using std::vector;

#include "packet.pb.h"

#include "database.h"



int main(int argc, char* argv[])
{
    
    char cwd[1024];
    string currentDirectory;
    string databaseDirectory;
    if ( getcwd(cwd, sizeof(char) * 1024) != NULL) {
        currentDirectory = cwd;
        cout << endl << currentDirectory << endl;
        /*This block is only for these tests, and is intended to "go up" one level of the directory tree by removing the directory found (from the back of the string, delete characters up to and including the first "/")*/
        size_t found = currentDirectory.find_last_of("/");
        databaseDirectory = currentDirectory.substr(0, found);
        cout << endl << databaseDirectory << endl;
        /*End extra test block*/
    } else {
        perror("getcwd() error");
        return 0;
    }
    
    packet::Packet* dataPacket;                     //
    BCrypt bcrypt;                                  //
                                                    // Similar declarations will appear in the real client
    RSA::PublicKey publicKey;                       //
    RSA::PrivateKey privateKey;                     //
    string publicKeyString;                         //
    try
    {
        /* Testing key generation and encryption */
        ////////////////////////////////////////////////
        // Generate keys
        string privateKeyDirectory = currentDirectory + "/privateKey";
        publicKeyString = clientTools_h::KeyGen(privateKeyDirectory);

        string plain="Text to be recovered", cipher, recovered;
        
        //dataPacket->set_msg(0, plain);

        ////////////////////////////////////////////////
        // Encryption
        clientTools_h::LoadPublicKey(publicKeyString, publicKey);
        cipher = clientTools_h::Encrypt(publicKey, plain);

        clientTools_h::LoadPrivateKey(privateKeyDirectory, privateKey);
        
        cout << endl << "The public key is saved as the string:\n" << publicKeyString << endl;
        ////////////////////////////////////////////////
        ////////////////////////////////////////////////

        ////////////////////////////////////////////////
        // Decryption
        recovered = clientTools_h::Decrypt(privateKey, cipher);

        assert( plain == recovered );
        cout << endl << "The original text has been successfully recovered" << endl;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }
    
    /* End key and encryption tests*/
    
    /* Tests to ensure that user registering works */
    string user = "Jody";
    string password = "alsoABadpassword";
    string salt = clientTools_h::GetRandomSalt();
    cout << "Jody's salt is:" << salt << endl;
    string key = publicKeyString;
    string hash = bcrypt.generateHash(password.append(salt));
    
    string enteredPassword = "alsoABadpassword";
    string incorrectPassword = "alsoaBadpassword";
    if(database_h::FindUser(user, databaseDirectory)){
        cout << "Jody already exists" << endl;
    }else{
        database_h::CreateUser(user, hash, salt, key, databaseDirectory);
    }
    
    if(database_h::FindUser(user, databaseDirectory)){
        vector<string> joeyPass = database_h::GetPassword(user, databaseDirectory);
        assert(bcrypt.validatePassword(enteredPassword.append(joeyPass.at(1)),joeyPass.at(0)));
        assert(!bcrypt.validatePassword(incorrectPassword.append(joeyPass.at(1)),joeyPass.at(0)));
        cout << "Jody's password successfully validated" << endl;
    }else{
        cout << "User not found in database" << endl;
    }
    
    if(database_h::FindUser(user, databaseDirectory)){
        vector<string> joeyKey = database_h::GetPublicKey(user, databaseDirectory);
        assert(joeyKey.at(0) == key);
    }else{
        cout << "User not found in database" << endl;
    }
    
    /* End user registry tests */

	return 0;
}

