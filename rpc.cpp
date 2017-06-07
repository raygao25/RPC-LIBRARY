#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <vector>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <iostream>
#include "rpc.h"
#include "binder.h"

using namespace std;

int Global_server_binder_socket = 0;
int Global_server_client_socket = 0;
int Global_server_port = 0;
int Global_client_binder_socket = 0;
char *Global_binder_addr;

struct fn_data {
    char* name;
    skeleton fn;
    int *argTypes;
};

vector<fn_data> fn_db;

struct Server {
    char hostname[256];
    int port;
    Server(char *name, int portnum) {
        strcpy(hostname, name);
        port = portnum;
    }
};

struct Function {
    char *name;
    int *argTypes;
    vector<Server> server_list;
    Function(char *name, int *argTypes) :name(name), argTypes(argTypes){}
};

vector<Function> function_list;

vector<Server> get_server_list(char *name, int *argTypes) {
    vector<Server> slist;
    for (int i = 0; i < function_list.size(); i++) {
        if (strcmp(name, function_list[i].name) == 0) {
            for (int j = 0; ; j++) {
                if (function_list[i].argTypes[j] == 0) {
                    if (argTypes[j] != 0) {
                        break;
                    }
                    return function_list[i].server_list;
                } else if (argTypes[j] == 0) {
                    break;
                }
                unsigned a1_front = function_list[i].argTypes[j] & 0xFFFF0000;
                unsigned a1_back = function_list[i].argTypes[j] & 0x0000FFFF;
                unsigned a2_front = argTypes[j] & 0xFFFF0000;
                unsigned a2_back = argTypes[j] & 0x0000FFFF;
                if (a1_front != a2_front) break;
                if ((a1_back == 0) != (a2_back == 0)) break;
            }
        }
    }
    return slist;
}

int refresh(char *name, int *argTypes) {
    int argTypes_size = 0;
    if (argTypes) {
        for (int i = 0;; i++) {
            argTypes_size += 4;
            if (argTypes[i] == 0) break;
        }
    }
    char binder_hostname[256];
    char server_hostname[256];
    int clientSocket, binder_port, server_port, temp, len, args_size;
    struct sockaddr_in binder_addr;
    struct hostent *binder;
    int msg_length = 64 + argTypes_size;
    char msg[8+msg_length];
    long int returnValue;
    int errorCode;
len = 0;
    //building msg
    memcpy(msg, &msg_length, 4);
    temp = LOC_REQUEST_CACHE;
    memcpy(msg+4, &temp, 4);
    memcpy(msg+8, name, 64);
    memcpy(msg+72, argTypes, argTypes_size);
    //connect to binder
    strcpy(binder_hostname, getenv("BINDER_ADDRESS"));
    binder_port = atoi(getenv("BINDER_PORT"));
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0) {
        perror("ERROR opening socket");
        return ERROR_OPENING_SOCKET;
    }
    binder = gethostbyname(binder_hostname);
    if (binder == NULL) {
        perror("ERROR, no such host\n");
        return ERROR_BINDER_HOST_NOT_FOUND;
    }
    bzero((char *) &binder_addr, sizeof(binder_addr));
    binder_addr.sin_family = AF_INET;
    bcopy((char *)binder->h_addr, (char *)&binder_addr.sin_addr.s_addr, binder->h_length);
    binder_addr.sin_port = htons(binder_port);
    if (connect(clientSocket,(struct sockaddr *) &binder_addr,sizeof(binder_addr)) < 0) {
        perror("ERROR on connecting to binder");
        return ERROR_CANNOT_CONNET_TO_BINDER;
    }
    //connected
    Global_client_binder_socket = clientSocket;
    returnValue = write(clientSocket,msg,8+msg_length);
    if (returnValue < 0) {
        perror("ERROR writing to socket");
        return ERROR_WRITE_BINDER_SOCKET;
    }
    for (int i = 0; i < function_list.size(); i++) {
        if (strcmp(name, function_list[i].name) == 0) {
            for (int j = 0; ; j++) {
                if (function_list[i].argTypes[j] == 0) {
                    if (argTypes[j] != 0) {
                        break;
                    }
                    function_list.erase(function_list.begin()+i);
                    break;
                } else if (argTypes[j] == 0) {
                    break;
                }
                unsigned a1_front = function_list[i].argTypes[j] & 0xFFFF0000;
                unsigned a1_back = function_list[i].argTypes[j] & 0x0000FFFF;
                unsigned a2_front = argTypes[j] & 0xFFFF0000;
                unsigned a2_back = argTypes[j] & 0x0000FFFF;
                if (a1_front != a2_front) break;
                if ((a1_back == 0) != (a2_back == 0)) break;
            }
        }
    }
    //parse reply
    read(clientSocket, &len, 4);
    read(clientSocket, &temp, 4);
    if (temp == LOC_SUCCESS) {
        Function f(name, argTypes);
        for (int i = 0; i < len; i++) {
            read(clientSocket, server_hostname, 256);
            read(clientSocket, &server_port, 4);
            Server s(server_hostname, server_port);
            f.server_list.push_back(s);
        }
        function_list.push_back(f);
        return 0;
    } else {
        read(clientSocket, &errorCode, 4);
        if (errorCode == ERROR_NO_AVAILABLE_SERVER) {
            return ERROR_NO_AVAILABLE_SERVER;
        } else if (errorCode == ERROR_BINDER_SHUTTING_DOWN) {
            return ERROR_BINDER_SHUTTING_DOWN;
        }
        return ERROR_UNKNOWN;
    }
}

int argTypesLen(int * argTypes){
    int argNum = 0;
    while(argTypes[argNum] != 0){
        argNum++;
    }
    return argNum+1;
}

char *argsToBytes(int *argTypes, void **args, int* size){
    int length = 0;
    for (int i = 0; argTypes[i] != 0; ++i)
    {
        int arrayLength = (argTypes[i] << 16) >> 16;
        if (arrayLength == 0)
            arrayLength = 1;
        int type = (argTypes[i] << 2) >> 18;
        if (type == ARG_CHAR)
            length += arrayLength*sizeof(char);
        if (type == ARG_SHORT)
            length += arrayLength*sizeof(short);
        if (type == ARG_INT)
            length += arrayLength*sizeof(int);
        if (type == ARG_LONG)
            length += arrayLength*sizeof(long);
        if (type == ARG_DOUBLE)
            length += arrayLength*sizeof(double);
        if (type == ARG_FLOAT)
            length += arrayLength*sizeof(float);
    }
    char *argsByte = (char *)malloc(length*sizeof(char));
    int index = 0;

    for (int i = 0; argTypes[i] != 0; ++i)
    {
        int arrayLength = (argTypes[i] << 16) >> 16;
        if (arrayLength == 0)
            arrayLength = 1;

        int type = (argTypes[i] << 2) >> 18;
        if (type == ARG_CHAR){
            memcpy(argsByte+index, args[i], arrayLength*sizeof(char));
            index += arrayLength*sizeof(char);
        }
        else if (type == ARG_SHORT){
            memcpy(argsByte+index, args[i], arrayLength*sizeof(short));
            index += arrayLength*sizeof(short);
        }
        else if (type == ARG_INT){
            memcpy(argsByte+index, args[i], arrayLength*sizeof(int));
            index += arrayLength*sizeof(int);
        }
        else if (type == ARG_LONG){
            memcpy(argsByte+index, args[i], arrayLength*sizeof(long));
            index += arrayLength*sizeof(long);
        }
        else if (type == ARG_DOUBLE){
            memcpy(argsByte+index, args[i], arrayLength*sizeof(double));
            index += arrayLength*sizeof(double);
        }
        else if (type == ARG_FLOAT){
            memcpy(argsByte+index, args[i], arrayLength*sizeof(float));
            index += arrayLength*sizeof(float);
        }

    }
    *size = length;
    return argsByte;
}



void **bytesToArgs(int *argTypes, char* bytes){
    int argNum = argTypesLen(argTypes) - 1;
    void **args = (void **)malloc(argNum*sizeof(void*));
    int index = 0;
    for (int i = 0; argTypes[i] != 0; ++i)
    {
        int arrayLength = (argTypes[i] << 16) >> 16;
        if (arrayLength == 0)
            arrayLength = 1;

        int type = (argTypes[i] << 2) >> 18;
        if (type == ARG_CHAR){
            args[i] = malloc(arrayLength*sizeof(char));
            memcpy(args[i], bytes+index, arrayLength*sizeof(char));
            index += arrayLength*sizeof(char);
        }
        else if (type == ARG_SHORT){
            args[i] = malloc(arrayLength*sizeof(short));
            memcpy(args[i], bytes+index, arrayLength*sizeof(short));
            index += arrayLength*sizeof(short);
        }
        else if (type == ARG_INT){
            args[i] = malloc(arrayLength*sizeof(int));
            memcpy(args[i], bytes+index, arrayLength*sizeof(int));
            index += arrayLength*sizeof(int);
        }
        else if (type == ARG_LONG){
            args[i] = malloc(arrayLength*sizeof(long));
            memcpy(args[i], bytes+index, arrayLength*sizeof(long));
            index += arrayLength*sizeof(long);
        }
        else if (type == ARG_DOUBLE){
            args[i] = malloc(arrayLength*sizeof(double));
            memcpy(args[i], bytes+index, arrayLength*sizeof(double));
            index += arrayLength*sizeof(double);
        }
        else if (type == ARG_FLOAT){
            args[i] = malloc(arrayLength*sizeof(float));
            memcpy(args[i], bytes+index, arrayLength*sizeof(float));
            index += arrayLength*sizeof(float);
        }
    }
    return args;
}

int rpcCall(char *name, int *argTypes, void **args) {
    int argTypes_size = 0;
    if (argTypes) {
        for (int i = 0;; i++) {
            argTypes_size += 4;
            if (argTypes[i] == 0) break;
        }
    }
    char binder_hostname[256];
    char server_hostname[256];
    int clientSocket, binder_port, server_port, temp, len, args_size, server_msg_length;
    struct sockaddr_in binder_addr, server_addr;
    struct hostent *binder, *server;
    int msg_length = 64 + argTypes_size;
    char msg[8+msg_length];
    char *ptr = msg;
    char reply[8+256+4];
    long int returnValue;
    int errorCode;
    //building msg
    memcpy(ptr, &msg_length, 4);
    ptr+=4;
    temp = LOC_REQUEST;
    memcpy(ptr, &temp, 4);
    ptr+=4;
    memcpy(ptr, name, 64);
    ptr+=64;
    memcpy(ptr, argTypes, argTypes_size);
    
    //connect to binder
    strcpy(binder_hostname, getenv("BINDER_ADDRESS"));
    binder_port = atoi(getenv("BINDER_PORT"));
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0) {
		perror("ERROR opening socket");
		return ERROR_OPENING_SOCKET;
	}
    binder = gethostbyname(binder_hostname);
    if (binder == NULL) {
        perror("ERROR, no such host\n");
        return ERROR_BINDER_HOST_NOT_FOUND;
    }
    bzero((char *) &binder_addr, sizeof(binder_addr));
    binder_addr.sin_family = AF_INET;
    bcopy((char *)binder->h_addr, (char *)&binder_addr.sin_addr.s_addr, binder->h_length);
    binder_addr.sin_port = htons(binder_port);
    if (connect(clientSocket,(struct sockaddr *) &binder_addr,sizeof(binder_addr)) < 0) {
		perror("ERROR on connecting to binder");
		return ERROR_CANNOT_CONNET_TO_BINDER;
    }
    //connected
    
    Global_client_binder_socket = clientSocket;
    returnValue = write(clientSocket,msg,8+msg_length);
    if (returnValue < 0) {
	    perror("ERROR writing to socket");
	    return ERROR_WRITE_BINDER_SOCKET;
    }
    returnValue = read(clientSocket,reply,268);
    if (returnValue < 0) {
	    perror("ERROR reading from socket");
	    return ERROR_READ_BINDER_SOCKET;
    }
    //parse reply
    ptr = reply + 4;
    memcpy(&temp, ptr, 4);
    ptr += 4;
    if (temp == LOC_SUCCESS) {
        memcpy(server_hostname, ptr, 256);
        ptr += 256;
        memcpy(&server_port, ptr, 4);
    } else {
	    memcpy(&errorCode, ptr, 4);
        if (errorCode == ERROR_NO_AVAILABLE_SERVER) {
            return ERROR_NO_AVAILABLE_SERVER;
        } else if (errorCode == ERROR_BINDER_SHUTTING_DOWN) {
            return ERROR_BINDER_SHUTTING_DOWN;
        }
        return ERROR_UNKNOWN;
    }
    //close(clientSocket);
    
    //calling server
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    server = gethostbyname(server_hostname);
    if (!server) {
	    perror("Error, no such server");
	    return ERROR_SERVER_HOST_NOT_FOUND;
    }
    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
    server_addr.sin_port = htons(server_port);
    if (connect(clientSocket,(struct sockaddr *) &server_addr,sizeof(server_addr)) < 0) {
	    fprintf(stderr,"ERROR, cannot connect to server\n");
	    return ERROR_CANNOT_CONNET_TO_SERVER;
    }
    
    char *argsByte = argsToBytes(argTypes, args, &args_size);

    server_msg_length = 64 + 4 + argTypes_size + 4 + args_size;//name +sizeof type+type+sizeof args+args
    char server_msg[server_msg_length + 8];
    ptr = server_msg;
    memcpy(ptr, &server_msg_length, 4);
    ptr+=4;
    temp = EXECUTE;
    memcpy(ptr, &temp, 4);
    ptr+=4;
    memcpy(ptr, name, 64);
    ptr+=64;
    memcpy(ptr, &argTypes_size, 4);
    ptr+=4;
    memcpy(ptr, argTypes, argTypes_size);
    ptr+=argTypes_size;
    memcpy(ptr, &args_size, 4);
    ptr+=4;
    memcpy(ptr, argsByte, args_size);
    
    //write
    returnValue = write(clientSocket,server_msg,8+server_msg_length);
    if (returnValue < 0){ 
        perror("ERROR writing to socket");
        return ERROR_WRITE_SERVER_SOCKET;
    }
    //read

    returnValue = read(clientSocket,&len,4);
    returnValue = read(clientSocket,&temp,4);
    if (returnValue < 0) {
        perror("ERROR reading from socket");
        return ERROR_READ_SERVER_SOCKET;
    }
    if (temp == EXECUTE_SUCCESS) {
        char buffer[len];
        returnValue = read(clientSocket,buffer,len);
        void** tempargs = bytesToArgs(argTypes, buffer);
        for (int i = 0; i <(argTypes_size/4 -1) ; ++i) {
            args[i] = tempargs[i];
        }
    } else if (temp == EXECUTE_FAILURE) {
        read(clientSocket, &errorCode, 4);
        return errorCode;
    } else {
	    return ERROR_UNKNOWN;
    }
    return 0;
}

int rpcCacheCall(char* name, int* argTypes, void** args) {
    int argTypes_size = 0;
    if (argTypes) {
        for (int i = 0;; i++) {
            argTypes_size += 4;
            if (argTypes[i] == 0) break;
        }
    }
    char binder_hostname[256];
    char server_hostname[256];
    int clientSocket, binder_port, server_port, temp, len, args_size, server_msg_length;
    struct sockaddr_in binder_addr, server_addr;
    struct hostent *binder, *server;
    int msg_length = 64 + argTypes_size;
    char msg[8+msg_length];
    char *ptr = msg;
    char reply[8+256+4];
    long int returnValue;
    int errorCode;
    //find server in local database
    vector<Server> server_list = get_server_list(name, argTypes);
    for (int i = 0; i < server_list.size(); i++) {
        char *server_host = server_list[i].hostname;
        server_port = server_list[i].port;
        clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        server = gethostbyname(server_host);
        if (!server) {
            continue;
        }
        bzero((char *) &server_addr, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
        server_addr.sin_port = htons(server_port);
        if (connect(clientSocket,(struct sockaddr *) &server_addr,sizeof(server_addr)) < 0) continue;
        char *argsByte = argsToBytes(argTypes, args, &args_size);
        server_msg_length = 64 + 4 + argTypes_size + 4 + args_size;//name +sizeof type+type+sizeof args+args
        char server_msg[server_msg_length + 8];
        ptr = server_msg;
        memcpy(ptr, &server_msg_length, 4);
        ptr+=4;
        temp = EXECUTE;
        memcpy(ptr, &temp, 4);
        ptr+=4;
        memcpy(ptr, name, 64);
        ptr+=64;
        memcpy(ptr, &argTypes_size, 4);
        ptr+=4;
        memcpy(ptr, argTypes, argTypes_size);
        ptr+=argTypes_size;
        memcpy(ptr, &args_size, 4);
        ptr+=4;
        memcpy(ptr, argsByte, args_size);
        returnValue = write(clientSocket,server_msg,8+server_msg_length);
        if (returnValue < 0) continue;
        returnValue = read(clientSocket,&len,4);
        returnValue = read(clientSocket,&temp,4);
        if (returnValue < 0) continue;
        if (temp == EXECUTE_SUCCESS) {
            char buffer[len];
            returnValue = read(clientSocket,buffer,len);
            void** tempargs = bytesToArgs(argTypes, buffer);
            for (int i = 0; i <(argTypes_size/4 -1) ; ++i) {
                args[i] = tempargs[i];
            }
            return 0;
        } else {
            continue;
        }
    }
    //failed to find a server in local db
cerr << "call refresh" << endl;
    returnValue = refresh(name, argTypes);
cerr << "refreshed" << endl;
    if (returnValue != 0) return returnValue;
    server_list = get_server_list(name, argTypes);
    for (int i = 0; i < server_list.size(); i++) {
        char *server_host = server_list[i].hostname;
        server_port = server_list[i].port;
        clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        server = gethostbyname(server_host);
        if (!server) {
            errorCode = ERROR_SERVER_HOST_NOT_FOUND;
            continue;
        }
        bzero((char *) &server_addr, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
        server_addr.sin_port = htons(server_port);
        if (connect(clientSocket,(struct sockaddr *) &server_addr,sizeof(server_addr)) < 0) {
	        errorCode = ERROR_CANNOT_CONNET_TO_SERVER;
	        continue;
        }
        char *argsByte = argsToBytes(argTypes, args, &args_size);
        server_msg_length = 64 + 4 + argTypes_size + 4 + args_size;//name +sizeof type+type+sizeof args+args
        char server_msg[server_msg_length + 8];
        ptr = server_msg;
        memcpy(ptr, &server_msg_length, 4);
        ptr+=4;
        temp = EXECUTE;
        memcpy(ptr, &temp, 4);
        ptr+=4;
        memcpy(ptr, name, 64);
        ptr+=64;
        memcpy(ptr, &argTypes_size, 4);
        ptr+=4;
        memcpy(ptr, argTypes, argTypes_size);
        ptr+=argTypes_size;
        memcpy(ptr, &args_size, 4);
        ptr+=4;
        memcpy(ptr, argsByte, args_size);
        returnValue = write(clientSocket,server_msg,8+server_msg_length);
        if (returnValue < 0) {errorCode = ERROR_WRITE_SERVER_SOCKET;continue;}
        returnValue = read(clientSocket,&len,4);
        if (returnValue < 0) {errorCode = ERROR_READ_SERVER_SOCKET;continue;}
        returnValue = read(clientSocket,&temp,4);
        if (returnValue < 0) {errorCode = ERROR_READ_SERVER_SOCKET;continue;}
        if (temp == EXECUTE_SUCCESS) {
            char buffer[len];
            returnValue = read(clientSocket,buffer,len);
            void** tempargs = bytesToArgs(argTypes, buffer);
            for (int i = 0; i <(argTypes_size/4 -1) ; ++i) {
                args[i] = tempargs[i];
            }
            return 0;
        } else {
	        errorCode = ERROR_UNKNOWN;
            continue;
        }
    }
    return errorCode;
}

int rpcTerminate(){
    int len = 0;
    int msg = TERMINATE;
    int rtv = write(Global_client_binder_socket, &len, 4);
    if (rtv < 0){
        return ERROR_WRITE_BINDER_SOCKET;
    }
    rtv = write(Global_client_binder_socket, &msg, 4);
    if (rtv < 0){
        return ERROR_WRITE_BINDER_SOCKET;
    }
    return 0;
}


int rpcInit(){

    int binder_socket, binder_port;
    struct hostent *binder;
    struct sockaddr_in binder_addr, server_addr;

    binder_port = atoi(getenv("BINDER_PORT"));
    binder_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (binder_socket < 0){ 
        perror("ERROR opening socket");
        return ERROR_OPENING_SOCKET;
    }
    binder = gethostbyname(getenv("BINDER_ADDRESS"));
    if (binder == NULL) return ERROR_BINDER_HOST_NOT_FOUND;
    bzero((char*) &binder_addr, sizeof(binder_addr));
    binder_addr.sin_family = AF_INET;
    bcopy((char *)binder->h_addr, 
         (char *)&binder_addr.sin_addr.s_addr,
         binder->h_length);
    binder_addr.sin_port = htons(binder_port);
    if (connect(binder_socket,(struct sockaddr *) &binder_addr,sizeof(binder_addr)) < 0){ 
        perror("ERROR connecting");
        return ERROR_CANNOT_CONNET_TO_BINDER;
    }

    Global_binder_addr = (char*)malloc(32*sizeof(char));
    memset(Global_binder_addr, NULL,32);
    memcpy(Global_binder_addr, inet_ntoa(binder_addr.sin_addr),strlen(inet_ntoa(binder_addr.sin_addr)));
    Global_server_binder_socket = binder_socket;

    Global_server_client_socket = socket(AF_INET, SOCK_STREAM, 0);
    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(0);
    if (bind(Global_server_client_socket, (struct sockaddr *)&server_addr,
          sizeof(server_addr)) < 0) {
        printf("ERROR binding port to socket\n");
        return ERROR_BINDING_PORT;
    }
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    getsockname(Global_server_client_socket, (struct sockaddr *)&sin, &len);
    Global_server_port = ntohs(sin.sin_port);

    return 0;
}




bool fncmp(fn_data cand, char* name, int* argTypes){
    if (strcmp(cand.name, name) != 0)
        return false;
    if (argTypesLen(argTypes) != argTypesLen(cand.argTypes))
        return false;
    for (int i = 0; i < argTypesLen(argTypes); ++i)
    {
        unsigned a1_front = cand.argTypes[i] & 0xFFFF0000;
        unsigned a1_back = cand.argTypes[i] & 0x0000FFFF;
        unsigned a2_front = cand.argTypes[i] & 0xFFFF0000;
        unsigned a2_back = cand.argTypes[i] & 0x0000FFFF;
        if (a1_front != a2_front) return false;
        if ((a1_back == 0) != (a2_back == 0)) return false;
    }
    return true;
}



int rpcRegister(char* name, int* argTypes, skeleton f){
    
        int len;


    int message_length = 324 + argTypesLen(argTypes)*4;
    char message[message_length+8];
    char hostname[256];
    bzero(hostname, 256);
    gethostname(hostname, 255);
    int message_type = REGISTER;

    memcpy(message, &message_length, 4);
    memcpy(message+4, &message_type, 4);
    memcpy(message+8, hostname, 256);
    memcpy(message+264, &Global_server_port, 4);
    memcpy(message+268, name, 64);
    memcpy(message+332,argTypes, argTypesLen(argTypes)*4);

    int rtv = write(Global_server_binder_socket, message, message_length+8);
    if (rtv < 0) return ERROR_WRITE_BINDER_SOCKET;
    int errorMsg = 0;
    rtv = read(Global_server_binder_socket, &len, 4);
    if (rtv < 0) return ERROR_READ_BINDER_SOCKET;
    rtv = read(Global_server_binder_socket, &errorMsg, 4);
    if (rtv < 0) return ERROR_READ_BINDER_SOCKET;
    if (errorMsg == REGISTER_FAILURE){
        printf("Registration failed with error: %d\n", errorMsg);
    }else {
        fn_data newfn = {};
        newfn.name = name;
        newfn.fn = f;
        newfn.argTypes = argTypes;

        for (int i = 0; i < fn_db.size(); ++i)
        {
            if (fncmp(fn_db[i], name, argTypes))
            {
                fn_db.erase(fn_db.begin()+i);
                break;
            }
        }

        fn_db.push_back(newfn);
    }

    return 0;
}




void* requestHandler(void *arguments){
    int rtv, message_length,message_type,client_socket, argTypes_size, argsByte_size;

    client_socket = ((int *)arguments)[0];
    message_length = ((int *)arguments)[1];
    /////
    char hostname[256];
    gethostname(hostname, 256);
    printf("host %s handling request\n", hostname);
    ////

    //rtv = read(client_socket, &message_length, 4);
    char buffer[message_length+4];
    rtv = read(client_socket,buffer, message_length+4);
    memcpy(&message_type, buffer, 4);
    if (message_type != EXECUTE){
        printf("Wrong message from client.\n");
    }

    char name[64];
    bzero(name, 64);
    memcpy(name, buffer+4, 64);

    memcpy(&argTypes_size, buffer+68, 4);
    int argTypes[argTypes_size/4];
    memcpy(argTypes, buffer+72, argTypes_size);
    memcpy(&argsByte_size, buffer+72+argTypes_size, 4);
    char argsByte[argsByte_size];
    memcpy(argsByte, buffer+76+argTypes_size, argsByte_size);
    void **args = bytesToArgs(argTypes, argsByte);

    for (int i = 0; i < fn_db.size(); ++i)
    {
        if (fncmp(fn_db[i], name, argTypes))
        {
            rtv = (fn_db[i].fn)(argTypes, args);
            break;
        }else{
            if (i == (fn_db.size()-1)){
                rtv =ERROR_FUNCTION_NOT_FOUND;
            }
        }
    }
    if (rtv == 0) { //success
        int rtvalueLength = 0;
        char *rtvalue = argsToBytes(argTypes, args, &rtvalueLength);
        char reply[rtvalueLength+8];
        memcpy(reply, &rtvalueLength, 4);
        int msgType = EXECUTE_SUCCESS;
        memcpy(reply+4, &msgType, 4);
        memcpy(reply+8, rtvalue, rtvalueLength);

        write(client_socket, reply, rtvalueLength+8);
    }
    else{
        int msgType = EXECUTE_FAILURE;
        int msgLength = 4;
        char reply[12];
        memcpy(reply, &msgLength, 4);
        memcpy(reply+4, &msgType, 4);
        memcpy(reply+8, &rtv, 4);
        write(client_socket, reply, 12);
    }
    return NULL;
}


int rpcExecute(){
    int client_socket,msgLength;
    socklen_t clilen;
    struct sockaddr_in cli_addr;
    listen(Global_server_client_socket, 20);

    fd_set clientfds;
    clilen = sizeof(cli_addr);

    while(true){
        FD_ZERO(&clientfds);
        FD_SET(Global_server_client_socket, &clientfds);

        int activity = select(Global_server_client_socket+1, &clientfds, NULL,NULL,NULL);
        client_socket = accept(Global_server_client_socket, (struct sockaddr *) &cli_addr, &clilen);


        read(client_socket, &msgLength, 4);
        if (msgLength != 0)
        {
            int *buffer = (int *)malloc(2*sizeof(int));
            buffer[0] = client_socket;
            buffer[1] = msgLength;
            pthread_t handler;
            pthread_create(&handler, NULL, requestHandler, buffer);
        }else{

            char * addr = (char *)malloc(32*sizeof(char));
            memset(addr, NULL,32);
            memcpy(addr, inet_ntoa(cli_addr.sin_addr), strlen(inet_ntoa(cli_addr.sin_addr)));
            if (strcmp(addr, "127.0.0.1") || strcmp(addr, "127.0.1.1") || strcmp(addr, Global_binder_addr)){
                int msgType =0;
                read(client_socket, &msgType, 4);
                if (msgType == TERMINATE)
                {
                    msgType = TERMINATE_ACK;
                    write(Global_server_binder_socket, &msgLength, 4);
                    write(Global_server_binder_socket, &msgType, 4);
                }
                return 0;
            }
        }
    }
}









