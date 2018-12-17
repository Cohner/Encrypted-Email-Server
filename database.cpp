#include "database.h"
#include <stdio.h>
#include <sqlite3.h>
#include <string>
#include <vector>
#include <iostream>
using namespace std;

static int database_h::callback(void *outputPtr, int argc, char **argv, char **azColName){
    for(int i = 0; i < argc; i++){
        vector<string> *list = reinterpret_cast<vector<string>*>(outputPtr);
        list->push_back(argv[i]);
    }
    return 0;
}

int database_h::CreateDatabase(string databaseDirectory){
    sqlite3* db;
    char *zErrMsg = 0;
    int rc;
    string sql;
    
    rc = sqlite3_open(databaseDirectory.c_str(), &db);
    if( rc ){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }
    
    sql = "CREATE TABLE IF NOT EXISTS USERS( ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT, PASSWORD TEXT, SALT BLOB, PUB_KEY BLOB);";
    rc = sqlite3_exec(db, sql.c_str(), callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return 0;
    }else{
        fprintf(stdout, "Users Table created successfully or already exists\n");
    }
    
    sql = "CREATE TABLE IF NOT EXISTS MSG( MSG_ID INTEGER PRIMARY KEY AUTOINCREMENT, FROM_WHO TEXT, TO_WHO TEXT, SUBJECT TEXT, MESSAGE TEXT);";
    rc = sqlite3_exec(db, sql.c_str(), callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return 0;
    }else{
        fprintf(stdout, "Message Table created successfully or already exists\n");
    }
    
    sqlite3_close(db);
    return 1;
}

int database_h::FindUser(string user, string databaseDirectory){
    sqlite3* db;
    char * zErrMsg = 0;
    int rc;
    user = sqlite3_mprintf(user.c_str()); //Sanitize user input
    
    rc = sqlite3_open(databaseDirectory.c_str(), &db);
    if( rc ){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }
    
    string sql = "SELECT NAME FROM USERS WHERE NAME=\""+user+"\";";
    vector<string> results;
    
    rc = sqlite3_exec(db, sql.c_str(), callback, &results, &zErrMsg);
    if( rc != SQLITE_OK ){
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    }else{
        sqlite3_close(db);
      if (results.empty()){
        return 0; //Return false if the user does not exist
      } else {
        return 1; //Return true is the user exists
      }
    }
    sqlite3_close(db);
    return 0;
}

void database_h::CreateUser(string user, string password, string salt, string publicKey, string databaseDirectory){
    sqlite3* db;
    char * zErrMsg = 0;
    int rc;
    sqlite3_stmt *stmt = NULL;
    
    rc = sqlite3_open(databaseDirectory.c_str(), &db);
    if( rc ){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }


    rc = sqlite3_prepare_v2(db,
                            "INSERT INTO USERS(NAME, PASSWORD, SALT, PUB_KEY)"
                            " VALUES(?, ?, ?, ?)",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cerr << "prepare failed: " << sqlite3_errmsg(db) << endl;
    } else {
        // SQLITE_STATIC because the statement is finalized
        // before the buffer is freed:
        rc = sqlite3_bind_text(stmt, 1, user.c_str(), user.size(), SQLITE_STATIC);
        rc = sqlite3_bind_text(stmt, 2, password.c_str(), password.size(), SQLITE_STATIC);
        rc = sqlite3_bind_blob(stmt, 3, salt.c_str(), salt.size(), SQLITE_STATIC);
        rc = sqlite3_bind_blob(stmt, 4, publicKey.c_str(), publicKey.size(), SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            cerr << "bind failed: " << sqlite3_errmsg(db) << endl;
        } else {
            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE)
                cerr << "execution failed: " << sqlite3_errmsg(db) << endl;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return;
}

//This function returns an array with item 0 being the hashed password, and item 1 being the salt
vector<string> database_h::GetPassword(string user, string databaseDirectory){
    sqlite3* db;
    char * zErrMsg = 0;
    int rc;
    user = sqlite3_mprintf(user.c_str()); //Sanitize user input
    vector<string> results;
    
    rc = sqlite3_open(databaseDirectory.c_str(), &db);
    if( rc ){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return results;
    }
    
    string sql = "SELECT PASSWORD, SALT FROM USERS WHERE NAME=\""+user+"\";";

    rc = sqlite3_exec(db, sql.c_str(), callback, &results, &zErrMsg);
    if( rc != SQLITE_OK ){
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    }else{
        sqlite3_close(db);
        return results;
    }
    sqlite3_close(db);
    return results;
    
    
}

void database_h::WriteMessage(string user, string sendTo, string subject, string message, string databaseDirectory){
    sqlite3* db;
    char * zErrMsg = 0;
    int rc;
    user = sqlite3_mprintf(user.c_str()); //Sanitize user input
    sendTo = sqlite3_mprintf(sendTo.c_str());
    subject = sqlite3_mprintf(subject.c_str());
    message = sqlite3_mprintf(message.c_str());
    
    rc = sqlite3_open(databaseDirectory.c_str(), &db);
    if( rc ){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }
    
    string sql = "INSERT INTO MSG (\"FROM_WHO\",\"TO_WHO\",\"SUBJECT\",\"MESSAGE\") VALUES(\""+user+"\",\""+sendTo+"\",\""+subject+"\",\""+message+"\");";
    rc = sqlite3_exec(db, sql.c_str(), callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    }else{
        sqlite3_close(db);
        cout << "User created" << endl;
    }
    sqlite3_close(db);
    return;
}

void database_h::GetMessages(packet::Packet* dataPacket, string user, string databaseDirectory){
    sqlite3* db;
    char * zErrMsg = 0;
    int rc;
    user = sqlite3_mprintf(user.c_str()); //Sanitize user input
    string sql;
    
    vector<string> from;
    vector<string> subject;
    vector<string> message;
    
    rc = sqlite3_open(databaseDirectory.c_str(), &db);
    if( rc ){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }
    
    sql = "SELECT FROM_WHO FROM MSG WHERE TO_WHO=\""+user+"\";";

    rc = sqlite3_exec(db, sql.c_str(), callback, &from, &zErrMsg);
    if( rc != SQLITE_OK ){
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    }else{
        sqlite3_close(db);
        return;
    }
    
    sql = "SELECT SUBJECT FROM MSG WHERE TO_WHO=\""+user+"\";";

    rc = sqlite3_exec(db, sql.c_str(), callback, &subject, &zErrMsg);
    if( rc != SQLITE_OK ){
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    }else{
        sqlite3_close(db);
        return;
    }
    
    sql = "SELECT MESSAGE FROM MSG WHERE TO_WHO=\""+user+"\";";

    rc = sqlite3_exec(db, sql.c_str(), callback, &message, &zErrMsg);
    if( rc != SQLITE_OK ){
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    }else{
        sqlite3_close(db);
        return;
    }
    
    for(int i = 0; i < from.size(); i++){
        dataPacket->set_from(i, from.at(i));
    }
    
    for(int i = 0; i < subject.size(); i++){
        dataPacket->set_subject(i, subject.at(i));
    }
    
    for(int i = 0; i < message.size(); i++){
        dataPacket->set_msg(i, message.at(i));
    }
    
    sqlite3_close(db);
    return;
}

vector<string> database_h::GetPublicKey(string user, string databaseDirectory){
    sqlite3* db;
    char * zErrMsg = 0;
    int rc;
    user = sqlite3_mprintf(user.c_str()); //Sanitize user input
    
    vector<string> results;
    
    rc = sqlite3_open(databaseDirectory.c_str(), &db);
    if( rc ){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return results;
    }
    
    string sql = "SELECT PUB_KEY FROM USERS WHERE NAME=\""+user+"\";";

    rc = sqlite3_exec(db, sql.c_str(), callback, &results, &zErrMsg);
    if( rc != SQLITE_OK ){
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    }else{
        sqlite3_close(db);
        return results;
    }
    sqlite3_close(db);
    return results;
}

vector<string> database_h::GetAllUsers(string databaseDirectory){
    sqlite3* db;
    char * zErrMsg = 0;
    int rc;
    
    vector<string> results;
    
    rc = sqlite3_open(databaseDirectory.c_str(), &db);
    if( rc ){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return results;
    }
    
    string sql = "SELECT NAME FROM USERS;";
    
    rc = rc = sqlite3_exec(db, sql.c_str(), callback, &results, &zErrMsg);
    if( rc != SQLITE_OK ){
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    }else{
        sqlite3_close(db);
        return results;
    }
    sqlite3_close(db);
    return results;
}