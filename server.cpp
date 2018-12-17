#include <ctype.h> 
#include <stdio.h>  
#include <string.h>
#include <stdlib.h>  
#include <errno.h>  
#include <unistd.h>   
#include <arpa/inet.h>     
#include <sys/types.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <sys/time.h> 
#include <iostream>
#include <cstdio>
#include <string>
#include "bcrypt/BCrypt.hpp"
#include "database.h"
#include "packet.pb.h"

#define PORT 20987
#define STRING_SIZE 1024  

using namespace std;

int bytesReceived;

packet::Packet* dataPacket;

short SocketCreate(void){
    short hSocket;
    printf("Create the socket\n");
    hSocket = socket(AF_INET, SOCK_STREAM, 0);
    return hSocket;
}

int BindCreatedSocket(int hSocket){
    int iRetval=-1;
    int ClientPort = PORT;
    struct sockaddr_in  remote={0};
    remote.sin_family = AF_INET; /* Internet address family */
    remote.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
    remote.sin_port = htons(ClientPort); /* Local port */
    iRetval = bind(hSocket,(struct sockaddr *)&remote,sizeof(remote));
    return iRetval;
}

int main(int argc, char* argv[]){
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    
    BCrypt bcrypt;
    database_h::CreateDatabase();
    int socket_desc , sock , clientLen , read_size;
    struct sockaddr_in server , client;
    char client_message[200]={0};
    char message[100] = {0};
    const char *pMessage = "test";

    //Create socket
    socket_desc = SocketCreate();
    if (socket_desc == -1){
        printf("Could not create socket");
        return 1;
    }
    printf("Socket created\n");
    //Bind
    if( BindCreatedSocket(socket_desc) < 0){
        //print the error message
        perror("bind failed.");
        return 1;
    }
    printf("bind done\n");
    //Listen
    listen(socket_desc , 3);
    //Accept and incoming connection
    while(1){
        printf("Waiting for incoming connections...\n");
        clientLen = sizeof(struct sockaddr_in);
        
        //accept connection from an incoming client
        sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&clientLen);
        if (sock < 0){
            perror("accept failed");
            return 1;
        }
        printf("Connection accepted\n");
        memset(client_message, '\0', sizeof client_message);
        memset(message, '\0', sizeof message);
        
        
        while(1){
            //bytesReceived = recv(sock , &dataFromClient, 10000, MSG_PEEK);
            //recv(sock , &dataFromClient , bytesReceived , 0);
            if(dataPacket->op() == 1){
                //registerUser
                if(database_h::FindUser(dataPacket->name())){
                    dataPacket->set_error("Username Taken");
                    //send(sock , &dataFromClient , sizeof(dataFromClient) , 0);
                }else{
                    database_h::CreateUser(dataPacket->name(), dataPacket->password(), dataPacket->salt(), dataPacket->pubkey());
                    //send(sock , &dataFromClient , sizeof(dataFromClient) , 0);
                }
            }
            else if(dataPacket->op() == 2){
                //loginUser
                if(database_h::FindUser(dataPacket->name())){
                    string databasePassword = database_h::GetPassword(dataPacket->name()).at(0);
                    string userPassword = dataPacket->password();
                    if( databasePassword == userPassword){
                        dataPacket->set_error("Login Success");
                        //send(sock , &dataFromClient , sizeof(dataFromClient) , 0);
                    }else{
                        dataPacket->set_error("Login Failed");
                        //send(sock , &dataFromClient , sizeof(dataFromClient) , 0);
                    }
                }else{
                    dataPacket->set_error("Login Failed");
                    //send(sock , &dataFromClient , sizeof(dataFromClient) , 0);
                }
                
            }
            else if(dataPacket->op() == 3){
                //sendMesage
                if(database_h::FindUser(dataPacket->to(0))){
                    database_h::WriteMessage(dataPacket->name(), dataPacket->to(0), dataPacket->subject(0), dataPacket->msg(0));
                }else{
                    dataPacket->set_error("User Not Found");
                    //SEND PACKET
                }
                //THIS DOES NOT SEND ANYTHING ELSE BACK TO USER IF NO ERROR
            }
            else if(dataPacket->op() == 4){
                //viewMessages
                database_h::GetMessages(dataPacket, dataPacket->name());
            }
            else if(dataPacket->op() == 5){
                //viewUsers
                int i;
                vector<string> allUsers = database_h::GetAllUsers();
                for(i = 0; i < allUsers.size(); i++){
                    dataPacket->set_all_users(i, allUsers.at(i));
                }
                // SEND PACKET
            }
        }
        
        
        printf("Client reply : %s\n",client_message);
        if(strcmp(pMessage,client_message)==0){
            strcpy(message,"Hi there!");
        }else{
            strcpy(message,"Invalid Message!");
        }
        // Send some data
        if(send(sock, message, strlen(message), 0) < 0){
            printf("Send failed");
            return 1;
        }
        close(sock);
        sleep(1);
    }
    return 0;
}


    /*******BEGIN TESTS*******
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
    *******END TESTS*******/