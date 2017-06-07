#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define REGISTER          10
#define REGISTER_SUCCESS  11
#define REGISTER_FAILURE  12
#define LOC_REQUEST       13
#define LOC_SUCCESS       14
#define LOC_FAILURE       15
#define EXECUTE           16
#define EXECUTE_SUCCESS   17
#define EXECUTE_FAILURE   18
#define TERMINATE         19
#define TERMINATE_ACK     20
#define LOC_REQUEST_CACHE 21

//error codes
#define ERROR_UNKNOWN                       -100
#define ERROR_OPENING_SOCKET                -1
#define ERROR_BINDER_HOST_NOT_FOUND        -201
#define ERROR_SERVER_HOST_NOT_FOUND        -202
#define ERROR_CANNOT_CONNET_TO_BINDER     -301
#define ERROR_CANNOT_CONNET_TO_SERVER     -302
#define ERROR_WRITE_BINDER_SOCKET              -401
#define ERROR_WRITE_CLIENT_SOCKET              -402
#define ERROR_WRITE_SERVER_SOCKET              -403
#define ERROR_READ_BINDER_SOCKET               -501
#define ERROR_READ_CLIENT_SOCKET               -502
#define ERROR_READ_SERVER_SOCKET               -503
#define ERROR_NO_AVAILABLE_SERVER       -6
#define ERROR_BINDER_SHUTTING_DOWN      -7
#define ERROR_BINDING_PORT              -8
#define ERROR_FUNCTION_NOT_FOUND        -9
#define ERROR_FD                        -10


struct func_entry {
    struct func_entry *next;
    char name[64];
    int *argTypes;
};

struct server_entry {
    struct server_entry *next;
    char hostname[256];
    int port;
    struct func_entry *head;
    struct func_entry *tail;
};

struct database {
    struct server_entry *head;
    struct server_entry *tail;
    int length;
};

struct database *db_create();

struct server_entry *find_server(struct database *db, char identifier[256], int port);

int cmp_functions(struct func_entry *f1, struct func_entry *f2);

int func_register(struct database *db, char identifier[256], int port, char name[64], int *argTypes);

int db_lookup(struct database *db, char name[64], int *argTypes, char server_identifier[256], int *server_port);

void print_db(struct database *db);

void free_db(struct database *db);

void error(const char *err_msg);


