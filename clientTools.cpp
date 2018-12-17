#include "clientTools.h"
#include <iostream>
#include <cstdio>
#include <string>
using namespace std;

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

//Generate the public and private key for this user, store the private key in a file, and return the public key as a string
string clientTools_h::KeyGen(const string& filename){
    AutoSeededRandomPool rng;
    RSA::PublicKey pubKey;
    RSA::PrivateKey secretKey;
    string pubKeyString;
    
    InvertibleRSAFunction parameters;
    parameters.GenerateRandomWithKeySize( rng, 3072 );

    RSA::PrivateKey privateKey( parameters );
    RSA::PublicKey publicKey( parameters );
    
    SavePrivateKey(filename, secretKey);
    SavePublicKey(&pubKeyString, pubKey);
    
    return pubKeyString;
}

void clientTools_h::SavePrivateKey(const string& filename, const RSA::PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	CryptoPP::ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void clientTools_h::SavePublicKey(string* stringname, const RSA::PublicKey& key) //This function will save a public key as a string
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	CryptoPP::ByteQueue queue;
	key.Save(queue);

	StringSave(stringname, queue);
}

void clientTools_h::Save(const string& filename, const CryptoPP::BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_sink.html
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

void clientTools_h::StringSave(string* stringname, const CryptoPP::BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_sink.html
	StringSink file(*stringname);
	bt.CopyTo(file);
	file.MessageEnd();
}


void clientTools_h::LoadPrivateKey(const string& filename, RSA::PrivateKey& key) 
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	CryptoPP::ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

void clientTools_h::LoadPublicKey(string stringname, RSA::PublicKey& key) //This function will load a public key from a string
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	CryptoPP::ByteQueue queue;

	StringLoad(&stringname, queue);
	key.Load(queue);	
}

void clientTools_h::Load(const string& filename, CryptoPP::BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_source.html
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

void clientTools_h::StringLoad(string* stringname, CryptoPP::BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_source.html
	StringSource file(*stringname, true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

string clientTools_h::Encrypt(RSA::PublicKey& pubKey, string message){
    string cipher;
    AutoSeededRandomPool rng;
    
    RSAES_OAEP_SHA_Encryptor e( pubKey );

        StringSource( message, true,
            new PK_EncryptorFilter( rng, e,
                new StringSink( cipher )
            ) // PK_EncryptorFilter
         ); // StringSource
    
    return cipher;
}

string clientTools_h::Decrypt(RSA::PrivateKey& privateKey, string cipher){
    string message;
    AutoSeededRandomPool rng;
    
    RSAES_OAEP_SHA_Decryptor d( privateKey );

        StringSource( cipher, true,
            new PK_DecryptorFilter( rng, d,
                new StringSink( message )
            ) // PK_EncryptorFilter
         ); // StringSource
    
    return message;
}

string clientTools_h::GetRandomSalt(){
	FILE* urandom;
	char randomData[50];
	urandom = fopen("/dev/urandom", "rb");
	if (urandom == NULL){
		
	    perror("/dev/urandom could not be accessed");
	    
	}else{

	    ssize_t result = fread(randomData, sizeof(char), sizeof(randomData), urandom);
	    if (result < 0){
	        perror("/dev/urandom could not be read");
	    }
	}
	
	string salt(randomData);
	return salt;
}