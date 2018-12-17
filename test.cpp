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
    
    string database = "testMail.db";                //
    string joeyKeyFile = "joeyPrivateKey";          //
    packet::Packet* dataPacket;                     //
    BCrypt bcrypt;                                  //
                                                    // Similar declarations will appear in the real client
    RSA::PublicKey publicKey;                       //
    RSA::PrivateKey privateKey;                     //
    string joeyPubKeyString;                        //
    try
    {
        database_h::CreateDatabase(database);
        /* Tests to ensure that user registering works, including key generation and storage */
        string joey = "Joey";
        string joeyPassword = "badpassword";
        string joeySalt = clientTools_h::GetRandomSalt();
        string joeyKey = clientTools_h::KeyGen(joeyKeyFile);
        string joeyHash = bcrypt.generateHash(joeyPassword.append(joeySalt));
        
        string joeyEnteredPassword = "badpassword";
        string joeyIncorrectPassword = "badpasword";
        if(database_h::FindUser(joey, database)){
            cout << "Joey already exists" << endl;
        }else{
            
            cout << "Joey's public key is:" << endl;
            cout << joeyKey << endl;
            database_h::CreateUser(joey, joeyHash, joeySalt, joeyKey, database);
            cout << "Joey added to database" << endl;
        }
        
        if(database_h::FindUser(joey, database)){
            vector<string> joeyPass = database_h::GetPassword(joey, database);
            assert(bcrypt.validatePassword(joeyEnteredPassword.append(joeyPass.at(1)),joeyPass.at(0)));
            assert(!bcrypt.validatePassword(joeyIncorrectPassword.append(joeyPass.at(1)),joeyPass.at(0)));
            cout << "Joey's password successfully validated" << endl;
        }else{
            cout << "User not found in database" << endl;
        }
        
        if(database_h::FindUser(joey, database)){
            vector<string> joeyStoredKey = database_h::GetPublicKey(joey, database);
            assert(joeyStoredKey.at(0) == joeyKey);
            joeyPubKeyString = joeyStoredKey.at(0);
        }else{
            cout << "User not found in database" << endl;
        }
        
        /* End user registry tests */
        

        /* Testing that joey can encrypt and decrypt using his own keys */
        ////////////////////////////////////////////////

        string plain="Text to be recovered", cipher, recovered;
        ////////////////////////////////////////////////
        // Encryption
        clientTools_h::LoadPublicKey(joeyPubKeyString, publicKey);
        cipher = clientTools_h::Encrypt(publicKey, plain);
        ////////////////////////////////////////////////
        ////////////////////////////////////////////////
        ////////////////////////////////////////////////
        // Decryption
        clientTools_h::LoadPrivateKey(joeyKeyFile, privateKey);
        recovered = clientTools_h::Decrypt(privateKey, cipher);

        assert( plain == recovered );
        cout << endl << "Joey's original text has been successfully recovered" << endl;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }
    
    /* End key and encryption tests for joey*/
    
    

	return 0;
}

