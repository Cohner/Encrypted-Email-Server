#include "clientTools.h"
#include <cstring>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string>
#include <time.h>
#include <vector>
#include <chrono>
#include <thread>
#include <termios.h>
#include "bcrypt/BCrypt.hpp"
#include "packet.pb.h"

#define PORT 20987
#define STRING_SIZE 1024

using namespace std;

int hSocket, read_size;
struct sockaddr_in server;

string userInput;
string __username__;
string __password__;
string __passwordConfirmation__;
BCrypt bcrypt;
int bytesReceived;

int userInterface(packet::Packet*);
void loginScreen(packet::Packet*);
void registerScreen(packet::Packet*);
void aboutScreen(packet::Packet*);
void serverUI(packet::Packet*);
void inbox(packet::Packet*);
void sendMessage(packet::Packet*);
void users(packet::Packet*);
int messageUI(int, packet::Packet*);



//Create a Socket for server communication
short SocketCreate(void){
    short hSocket;
    cout << "Create the socket\n";
    hSocket = socket(AF_INET, SOCK_STREAM, 0);
    return hSocket;
}
//try to connect with server
int SocketConnect(int hSocket){
 
    int iRetval=-1;
    int ServerPort = PORT;
    struct sockaddr_in remote={0};

    remote.sin_addr.s_addr = inet_addr("127.0.0.1"); //Local Host
    remote.sin_family = AF_INET;
    remote.sin_port = htons(ServerPort);

    iRetval = connect(hSocket , (struct sockaddr *)&remote , sizeof(struct sockaddr_in));

    return iRetval;
}
// Send the data to the server and set the timeout of 20 seconds
int SocketSend(int hSocket,char* Rqst,short lenRqst){
 
    int shortRetval = -1;
    struct timeval tv;
    tv.tv_sec = 20;  /* 20 Secs Timeout */
    tv.tv_usec = 0;  

    if(setsockopt(hSocket, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv,sizeof(tv)) < 0){
        cout << "Time Out\n";
        return -1;
    }
    shortRetval = send(hSocket , Rqst , lenRqst , 0);

    return shortRetval;
}
//receive the data from the server 
int SocketReceive(int hSocket,char* Rsp,short RvcSize){
    
    int shortRetval = -1;
    struct timeval tv;
    tv.tv_sec = 20;  /* 20 Secs Timeout */
    tv.tv_usec = 0;  
    
    if(setsockopt(hSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(tv)) < 0){
    cout << "Time Out\n";
    return -1;
    
    }
    shortRetval = recv(hSocket, Rsp , RvcSize , 0);
    
    cout << "Response %s\n" << Rsp;
    
    return shortRetval;
}
//helper function to hide password input
string getPASS(){
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    string PASS;
    cout << "Password: "; cin >> PASS; cout << endl;
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return PASS;
}

string getPASSConfirmation(){
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    string PASS;
    cout << "Confrim Password: "; cin >> PASS; cout << endl;
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return PASS;
}

void clearDataPacket(packet::Packet* dataPacket){
    dataPacket->set_op(0);
    dataPacket->clear_name();
    dataPacket->clear_password();
    dataPacket->clear_salt();
    dataPacket->clear_pubkey();
    dataPacket->clear_to();
    dataPacket->clear_from();
    dataPacket->clear_subject();
    dataPacket->clear_msg();
    dataPacket->clear_all_users();
    dataPacket->clear_error();
}

//helper function for more usable UI
void clearScreen(){
    cout << "\x1B[2J\x1B[H" << flush;
}

int userInterface(packet::Packet* dataPacket){
    clearScreen();
    cout << 
        "-------------------------------------------------\n"
        "*************************************************\n"
        "**                                             **\n"
        "** Welcome to Cohner and Justin's Email Server **\n"
        "**                                             **\n"
        "*************************************************\n"
        "                                                 \n"
        "Select an Option:\n"
        "\n"
        "1.) Login   2.) Register                         \n"
        "3.) About   4.) Exit                             \n"
        "                                                 \n"
        "->| ";
    cin >> userInput;
    if(userInput == "1"){
        dataPacket->set_op(2);
        loginScreen(dataPacket);
    }
    if(userInput == "2"){
        dataPacket->set_op(1);
        registerScreen(dataPacket);
    }
    if(userInput == "3"){
        aboutScreen(dataPacket);
    }
    if(userInput == "4"){
        exit(0);
    }else{
        userInterface(dataPacket);
    }
}

void loginScreen(packet::Packet* dataPacket){
    string temp;
    clearScreen();
    cout << 
        "-------------------------------------------------\n"
        "*************************************************\n"
        "**                                             **\n"
        "** Welcome to Cohner and Justin's Email Server **\n"
        "**                                             **\n"
        "*************************************************\n"
        "                                                 \n"
        "Username: ";
    cin >> __username__;
    dataPacket->set_name(__username__);
    clearScreen();
    cout << 
        "-------------------------------------------------\n"
        "*************************************************\n"
        "**                                             **\n"
        "** Welcome to Cohner and Justin's Email Server **\n"
        "**                                             **\n"
        "*************************************************\n"
        "                                                 \n"
        "Username: " << __username__ <<"\n";
    dataPacket->set_password(getPASS());
    
    /* TEMP REMOVAL OF SEND AND RECEIVE THESE FUNCTIONS SHOULD REQUEST THE HASHED PASSWORD AND THE SALT FROM THE SERVER
    send(hSocket , &dataToServer , sizeof(dataToServer) , 0);
    this_thread::sleep_until(chrono::system_clock::now() + chrono::seconds(1));
    bytesReceived = recv(hSocket, NULL, 10000, MSG_PEEK);
    recv(hSocket , &dataToServer , sizeof(dataToServer) , 0);
    */
    
    //TODO: VALIDATE THE PASSWORD BY HASHING THE PLAINTEXT WITH THE SALT FROM THE SERVER, THEN COMPARING THAT HASH TO THE HASH FROM THE SERVER
    // REPLACE THE IFS BELOW WITH NEW FUNCTIONALITY INVOLVING BCRYPT
    
    if(dataPacket->error() == "Login Success"){
        serverUI(dataPacket);
    }else if(dataPacket->error() == "Login Failed"){
        clearScreen();
        cout <<
            "-------------------------------------------------\n"
            "*************************************************\n"
            "**                                             **\n"
            "** Welcome to Cohner and Justin's Email Server **\n"
            "**                                             **\n"
            "*************************************************\n"
            "                                                 \n"
            "\033[1;31m        Username or Password is incorrect!\033[0m\n";
            this_thread::sleep_until(chrono::system_clock::now() + chrono::seconds(3));
            clearScreen();
            userInterface(dataPacket);
    }else{
       clearScreen();
        cout <<
            "-------------------------------------------------\n"
            "*************************************************\n"
            "**                                             **\n"
            "** Welcome to Cohner and Justin's Email Server **\n"
            "**                                             **\n"
            "*************************************************\n"
            "                                                 \n"
            "\033[1;31m        Username or Password is incorrect!\033[0m\n";
            this_thread::sleep_until(chrono::system_clock::now() + chrono::seconds(3));
            clearScreen();
            userInterface(dataPacket); 
    }
}

void serverUI(packet::Packet* dataPacket){
    clearScreen();
    cout <<
        "-------------------------------------------------\n"
        "*************************************************\n"
        "**                                             **\n"
        "**   Welcome, please select an option below    **\n"
        "**                                             **\n"
        "*************************************************\n"
        "Logged in as: " << __username__ << "\n"
        "\n"
        "1.) Inbox           2.) Send Message\n"
        "3.) View Users      4.) Logout\n"
        "\n"
        "->| ";
    cin >> userInput;
    if(userInput == "1"){
        dataPacket->set_op(4);
        inbox(dataPacket);
    }
    if(userInput == "2"){
        dataPacket->set_op(3);
        sendMessage(dataPacket);
    }
    if(userInput == "3"){
        dataPacket->set_op(5);
        users(dataPacket);
    }
    if(userInput == "4"){
        clearDataPacket(dataPacket);
        userInterface(dataPacket);
    }else{
        serverUI(dataPacket);
    }
} 

void registerScreen(packet::Packet* dataPacket){
    clearScreen();
    cout << 
        "-------------------------------------------------\n"
        "*************************************************\n"
        "**                                             **\n"
        "** Welcome to Cohner and Justin's Email Server **\n"
        "**                                             **\n"
        "*************************************************\n"
        "                                                 \n"
        "Please choose a username:                        \n"
        "->| ";
    cin >> __username__;
    dataPacket->set_name(__username__);
    
    clearScreen();
    cout << 
        "-------------------------------------------------\n"
        "*************************************************\n"
        "**                                             **\n"
        "** Welcome to Cohner and Justin's Email Server **\n"
        "**                                             **\n"
        "*************************************************\n"
        "                                                 \n"
        "Please choose a password:                        \n"
        "->| ";
    __password__ = getPASS();    
    __passwordConfirmation__ = getPASSConfirmation();
    
    if(__password__ == __passwordConfirmation__){
        //dataPacket->salt = to_string(rand());
        dataPacket->set_salt("salty");
        __password__ = bcrypt.generateHash(__password__.append(dataPacket->salt()));
        dataPacket->set_password(__password__);
        dataPacket->set_pubkey(clientTools_h::KeyGen("clientPrivateKey"));
    }else{
        clearScreen();
        cout <<
            "-------------------------------------------------\n"
            "*************************************************\n"
            "**                                             **\n"
            "** Welcome to Cohner and Justin's Email Server **\n"
            "**                                             **\n"
            "*************************************************\n"
            "                                                 \n"
            "\033[1;31m        Passwords do not match!\033[0m\n";
        this_thread::sleep_until(chrono::system_clock::now() + chrono::seconds(3));
        clearScreen();
        registerScreen(dataPacket);
    }
    
    /* TEMP REMOVAL OF SEND AND RECEIVE. THESE FUNCTIONS WILL SERIALZIE THE USER, AND SEND TO THE SERVER
    send(hSocket , &dataToServer , sizeof(dataToServer) , 0);
    bytesReceived = recv(hSocket, &dataToServer, 10000, MSG_PEEK);
    recv(hSocket, &dataToServer, bytesReceived, 0);
    */
    if(dataPacket->error() == "Username Taken"){
        clearScreen();
        cout <<
            "-------------------------------------------------\n"
            "*************************************************\n"
            "**                                             **\n"
            "** Welcome to Cohner and Justin's Email Server **\n"
            "**                                             **\n"
            "*************************************************\n"
            "                                                 \n"
            "\033[1;31m        Username is already taken!\033[0m\n";
        this_thread::sleep_until(chrono::system_clock::now() + chrono::seconds(3));
        clearScreen();
        clearDataPacket(dataPacket);
        registerScreen(dataPacket);
    }else{
        clearScreen();
        userInterface(dataPacket);
    }
}

void aboutScreen(packet::Packet* dataPacket){
     clearScreen();
     cout << 
        "-------------------------------------------------\n"
        "*************************************************\n"
        "**                                             **\n"
        "** Welcome to Cohner and Justin's Email Server **\n"
        "**                                             **\n"
        "*************************************************\n"
        "                                                 \n"
        "The project is to show our abilities we have \n"     
        "learned throughout the semester to write secure  \n"
        "software by leaving us with an open-ended project  \n"
        "which consists of creating an Email Server which  \n"
        "will require users to create a username and  \n"
        "password to login onto the server to use the  \n"
        "features including, but not exclusively, seeing  \n"
        "other registered users, sending, and receiving  \n"
        "messages from other registered users. \n"
        "\n"
        "Press '1' to go back. \n";
        cin >> userInput;
        if(userInput == "1"){
            userInterface(dataPacket);
        }else{
            aboutScreen(dataPacket);
        }
}

void inbox(packet::Packet* dataPacket){
    clearScreen();
    int i;
    // THIS NEEDS TO RECV RECIPIENT/SUBJECT/MSG/TIME
    // RECV
    cout <<
        "-------------------------------------------------\n"
        "*************************************************\n"
        "**                                             **\n"
        "**                    Inbox                    **\n"
        "**                                             **\n"
        "*************************************************\n"
        "\n\n"
        "Choose which message you want to read.\n";
    for(i = 0; i < dataPacket->subject_size(); i++){
        cout << "MSG: " << i+1 << "  FROM: " << dataPacket->to(i) 
        << "  SUBJECT: " << dataPacket->subject(i);
    }
    cin >> userInput;
    for(i = 0; i < dataPacket->subject_size(); i++){
        if(userInput == to_string(i-1)){
            messageUI(i, dataPacket);
        }
    }
    inbox(dataPacket);
}

int messageUI(int MSGNUM, packet::Packet* dataPacket){
    clearScreen();
    cout <<
        "-------------------------------------------------\n"
        "*************************************************\n"
        "**\n"
        "** RECIPIENT: " << dataPacket->to(MSGNUM) << "\n"
        "** SUBJECT: " << dataPacket->subject(MSGNUM) << "\n"
        "** \n"
        "*************************************************\n"
        "\n";
    cout << dataPacket->msg(MSGNUM) << "\n\n"
    "Press '1' to reply, any other key to go back.";
    cin >> userInput;
    if(userInput == "1"){
        clearScreen();
        cout <<
        "-------------------------------------------------\n"
        "*************************************************\n"
        "**\n"
        "** TEXT: ";
        cin >> userInput;
        dataPacket->set_op(3);
        dataPacket->set_to(0, dataPacket->to(MSGNUM));
        dataPacket->set_subject(0, dataPacket->subject(MSGNUM));
        dataPacket->set_msg(0, userInput);
        clearScreen();
        cout << "\n\n \033[1;31m        Message has been sent!\033[0m\n";
        // THIS NEEDS TO SEND OPTION/RECIPIENT/SUBJECT/MSG/
        // SEND
        this_thread::sleep_until(chrono::system_clock::now() + chrono::seconds(3));
    } else{
        inbox(dataPacket);
    }
    serverUI(dataPacket);
}

void sendMessage(packet::Packet* dataPacket){
    clearScreen();
    cout <<
        "-------------------------------------------------\n"
        "*************************************************\n"
        "**                                             **\n"
        "**     TO:                                       \n"
        "**     SUBJECT:                                  \n"
        "**                                             **\n"
        "*************************************************\n"
        "\n\n"
        "TO: ->| ";
    cin >> userInput;
    dataPacket->set_to(0, userInput);
    clearScreen();
    cout <<
        "-------------------------------------------------\n"
        "*************************************************\n"
        "**                                             **\n"
        "**     TO: " << dataPacket->to(0) <<               "\n"
        "**     SUBJECT:                                  \n"
        "**                                             **\n"
        "*************************************************\n"
        "\n\n"
        "SUBJECT: ->| ";
    cin >> userInput;
    dataPacket->set_subject(0, userInput);
    clearScreen();
    cout <<
        "-------------------------------------------------\n"
        "*************************************************\n"
        "**                                             **\n"
        "**     TO: " << dataPacket->to(0) <<               "\n"
        "**     SUBJECT: " << dataPacket->subject(0) <<     "\n"
        "**                                             **\n"
        "*************************************************\n"
        "\n\n"
        "MESSAGE: ->| ";
    cin >> userInput;
    dataPacket->set_msg(0, userInput);
    clearScreen();
    cout <<
        "-------------------------------------------------\n"
        "*************************************************\n"
        "** \n"
        "** IS THIS CORRECT? \n"
        "** TO: " << dataPacket->to(0) << "\n"
        "** SUBJECT: " << dataPacket->subject(0) << "\n"
        "** MESSAGE: " << dataPacket->msg(0) << "\n"
        "** \n\n"
        "PRESS 'Y' TO CONFIRM AND SEND \n"
        "OTHERWISE PRESS ANY OTHER KEY TO EDIT \n";
    cin >> userInput;
    if(userInput == "Y"){
        //SEND THE DATA
        //SEND THE DATA
        if(dataPacket->error() == "User Not Found"){
            cout << "\n\n \033[1;31m        Unable to find User!\033[0m\n";
            this_thread::sleep_until(chrono::system_clock::now() + chrono::seconds(3));
            serverUI(dataPacket);
        }else{
            cout << "\n\n \033[1;31m        Message has been sent!\033[0m\n";
            this_thread::sleep_until(chrono::system_clock::now() + chrono::seconds(3));
            serverUI(dataPacket);
        }
    }else{
        sendMessage(dataPacket);
    }
    serverUI(dataPacket);    
}

void users(packet::Packet* dataPacket){
    int i;
    clearScreen();
    cout <<
        "-------------------------------------------------\n"
        "*************************************************\n"
        "**                                             **\n"
        "**                  All Users                  **\n"
        "**                                             **\n"
        "*************************************************\n"
        "\n\n";
    for(i = 0; i < dataPacket->all_users_size(); i++){
        cout << i+1 << ".)" << dataPacket->all_users(i) << "\n";
    }
    cout << "Press '1 to go back. \n";
    cin >> userInput;
    if(userInput == "1"){
        serverUI(dataPacket);
    }else{
        users(dataPacket);
    }
    
}

int main(void){
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    packet::Packet* dataPacket;
    //Create socket
    hSocket = SocketCreate();
    if(hSocket == -1){
        cout << "Could not create socket\n";
    return 1;
    }
    cout << "Socket is created\n";
    //Connect to remote server
    if (SocketConnect(hSocket) < 0){
        perror("connect failed.\n");
        return 1;
    }
    cout << "Sucessfully conected with server\n";
    //clearScreen();
    userInterface(dataPacket);
    
    //Send data to the server
    //SocketSend(hSocket , SendToServer , strlen(SendToServer));
    //Received the data from the server
    //read_size = SocketReceive(hSocket , server_reply , 200);
    //cout << "Server Response : %s\n\n" << server_reply;
    
    close(hSocket);
    shutdown(hSocket,0);
    shutdown(hSocket,1);
    shutdown(hSocket,2);
    return 0;
}