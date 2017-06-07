#include "binder.h"


struct database *db_create() {
    struct database *db = (struct database *)malloc(sizeof(struct database));
    db->head = NULL;
    db->tail = NULL;
    db->length = 0;
    return db;
}

struct server_entry *find_server(struct database *db, char identifier[256], int port) {
    struct server_entry *target = NULL;
    for (struct server_entry *temp = db->head; temp; temp = temp->next) {
        if (strcmp(temp->hostname, identifier) == 0 && temp->port == port) {
            target = temp;
            break;
        }
    }
    return target;
}

int cmp_functions(struct func_entry *f1, struct func_entry *f2) {
    if (strcmp(f1->name,f2->name) == 0) {
        for (int i = 0; ; i++) {
            if (f1->argTypes[i] == 0) {
                if (f2->argTypes[i] != 0) {
                    return 0;
                }
                return 1;
            } else if (f2->argTypes[i] == 0) {
                return 0;
            }
            unsigned a1_front = f1->argTypes[i] & 0xFFFF0000;
            unsigned a1_back = f1->argTypes[i] & 0x0000FFFF;
            unsigned a2_front = f2->argTypes[i] & 0xFFFF0000;
            unsigned a2_back = f2->argTypes[i] & 0x0000FFFF;
            if (a1_front != a2_front) return 0;
            if ((a1_back == 0) != (a2_back == 0)) return 0;
        }
        return 1;
    }
    return 0;
}

int func_register(struct database *db, char identifier[256], int port, char name[64], int *argTypes) {
    struct func_entry *function = (struct func_entry *)malloc(sizeof(struct func_entry));
    function->next = NULL;
    memcpy(function->name, name, 64);
    function->argTypes = argTypes;
    if (db->length == 0) {//initialize database
        //create a new server entry
        struct server_entry *newserver = (struct server_entry *)malloc(sizeof(struct server_entry));
        newserver->next = NULL;
        memcpy(newserver->hostname,identifier, 256);
        newserver->port = port;
        newserver->head = function;
        newserver->tail = function;
        //add this server to database
        db->head = newserver;
        db->tail = newserver;
        db->length++;
        return 0;
    } else {
        struct server_entry *target = find_server(db,identifier,port);
        if (target) {
            for (struct func_entry *temp = target->head; temp; temp = temp->next) {
                if (cmp_functions(temp, function)) {
                    free(temp->argTypes);
                    temp->argTypes = function->argTypes;
                    free(function);
                    return 0;
                }
            }
            target->tail->next = function;
            target->tail = function;
        } else {
            struct server_entry *newserver = (struct server_entry *)malloc(sizeof(struct server_entry));
            memcpy(newserver->hostname,identifier, 256);
            newserver->port = port;
            newserver->head = function;
            newserver->tail = function;
            newserver->next = db->head;
            db->head = newserver;
            db->length++;
        }
    }
    return 0;
}

int db_lookup(struct database *db, char name[64], int *argTypes, char server_identifier[256], int *server_port) {
    struct server_entry *previous = db->head;
    for (struct server_entry *temp = db->head; temp; temp = temp->next) {
        for (struct func_entry *f = temp->head; f; f = f->next) {
            struct func_entry f2;
            memcpy(f2.name, name, 64);
            f2.argTypes = argTypes;
            if (cmp_functions(f, &f2)) {
                memcpy(server_identifier, temp->hostname, 256);
                *server_port = temp->port;
                if (temp == db->tail) {
                    return 1;
                }
                if (temp == db->head) {
                    db->tail->next = temp;
                    db->tail = temp;
                    db->head = temp->next;
                    temp->next = NULL;
                } else {
                    db->tail->next = temp;
                    db->tail = temp;
                    previous->next = temp->next;
                    temp->next = NULL;
                }
                return 1;
            }
        }
        previous = temp;
    }
    return 0;
}

int count_server(struct database *db, char name[64], int *argTypes) {
    int count = 0;
    for (struct server_entry *temp = db->head; temp; temp = temp->next) {
        for (struct func_entry *f = temp->head; f; f = f->next) {
            struct func_entry f2;
            memcpy(f2.name, name, 64);
            f2.argTypes = argTypes;
            if (cmp_functions(f, &f2)) {
                count++;
            }
        }
    }
    return count;
}

void print_db(struct database *db) {
    for (struct server_entry *temp = db->head; temp; temp = temp->next) {
        printf("Host name and port: %s, %d\n", temp->hostname, temp->port);
        for (struct func_entry *f = temp->head; f; f = f->next) {
            printf("	Function name: %s\n", f->name);
        }
    }
}

void free_db(struct database *db) {
    struct server_entry *s = db->head;
    while (s) {
        struct func_entry *f = s->head;
        while (f) {
            free(f->argTypes);
            struct func_entry *temp = f;
            f = f->next;
            free(temp);
        }
        struct server_entry *temp = s;
        s = s->next;
        free(temp);
    }
    free(db);
}


int main(int argc, const char * argv[]) {
    int binderSocket, connectionSocket, msg_length, msg_type, count;
    long int returnValue;
    socklen_t binderlen, clilen;
    struct sockaddr_in binder_addr, client_addr;
    fd_set active_fd, read_fd;
    char myhostname[256];
    struct database *database = db_create();
    int termination_flag = 0;
    int terminated_servers = 0;
    int active_servers = 0;
    char err_reply[12];
    
    binderSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (binderSocket < 0) exit(0);
    bzero((char *) &binder_addr, sizeof(binder_addr));
    binder_addr.sin_family = AF_INET;
    binder_addr.sin_addr.s_addr = INADDR_ANY;
    binder_addr.sin_port = htons(0);
    if (bind(binderSocket,(struct sockaddr *) &binder_addr,sizeof(binder_addr)) < 0) {
        exit(ERROR_BINDING_PORT);
    }
    
    listen(binderSocket, 1);
    binderlen = sizeof(binder_addr);
    getsockname(binderSocket, (struct sockaddr *) &binder_addr, &binderlen);
    gethostname(myhostname, 255);
    printf("BINDER_ADDRESS %s\n", myhostname);
    printf("BINDER_PORT %d\n", ntohs(binder_addr.sin_port));
    
    FD_ZERO (&active_fd);
    FD_SET (binderSocket, &active_fd);
    while (1) {
        read_fd = active_fd;
        if (select(FD_SETSIZE, &read_fd, NULL, NULL, NULL) < 0) {
            perror("ERROR on select");
            return ERROR_FD;
        }
        for (int i = 0; i < FD_SETSIZE; i++) {
            if (FD_ISSET(i, &read_fd)) {
                if (i == binderSocket) {
                    clilen = sizeof(client_addr);
                    connectionSocket = accept(binderSocket, (struct sockaddr *) &client_addr, &clilen);
                    if (connectionSocket < 0) break;
                    FD_SET(connectionSocket, &active_fd);
                }
                else {
                    returnValue = read(i,&msg_length,4);
                    if (returnValue == 0) {
                        close(i);
                        FD_CLR (i, &active_fd);
                        break;
                    }
                    returnValue = read(i,&msg_type,4);
                    if (returnValue == 0) break;
                    char name[64];
                    int *argTypes;
                    char server_identifier[256] = "";
                    int server_port, temp;
                    switch (msg_type) {
                        case REGISTER:
                            char reply[8];
                            temp = 0;
                            memcpy(reply, &temp, 4);
                            if (termination_flag) {
                                temp = REGISTER_FAILURE;
                                memcpy(reply+4, &temp, 4);
                                write(i, reply, 8);
                                break;
                            }
                            returnValue = read(i,server_identifier,256);
                            returnValue = returnValue | read(i,&server_port,4);
                            returnValue = returnValue | read(i,name,64);
                            if (returnValue< 0) return ERROR_READ_SERVER_SOCKET;
                            argTypes = (int *)malloc(msg_length - 324);
                            returnValue = read(i,argTypes,msg_length-324);
                            returnValue = func_register(database, server_identifier, server_port, name, argTypes);
                            temp = REGISTER_SUCCESS;
                            if (returnValue != 0) temp = REGISTER_FAILURE;
                            memcpy(reply+4, &temp, 4);
                            returnValue = write(i, reply, 8);
                            break;
                        case LOC_REQUEST:
                            temp = 0;
                            memcpy(err_reply, &temp, 4);
                            if (termination_flag) {
                                temp = LOC_FAILURE;
                                memcpy(err_reply+4, &temp, 4);
                                temp = ERROR_BINDER_SHUTTING_DOWN;
                                memcpy(err_reply+8, &temp, 4);
                                returnValue = write(i, err_reply, 12);
                                if (returnValue < 0) return ERROR_WRITE_CLIENT_SOCKET;
                                break;
                            }
                            returnValue = read(i,name,64);
                            argTypes = (int *)malloc(sizeof(int) * (msg_length-64));
                            returnValue = read(i,argTypes,msg_length-64);
                            if (returnValue< 0) return ERROR_WRITE_CLIENT_SOCKET;
                            returnValue = db_lookup(database, name, argTypes, server_identifier, &server_port);
                            if (returnValue) {
                                char reply[8+256+4];
                                temp = 260;
                                memcpy(reply, &temp, 4);
                                temp = LOC_SUCCESS;
                                memcpy(reply+4, &temp, 4);
                                memcpy(reply+8, server_identifier, 256);
                                memcpy(reply+264, &server_port, 4);
                                returnValue = write(i, reply, 268);
                                if (returnValue < 0) return ERROR_WRITE_CLIENT_SOCKET;
                            } else {
                                temp = LOC_FAILURE;
                                memcpy(err_reply+4, &temp, 4);
                                temp = ERROR_NO_AVAILABLE_SERVER;
                                memcpy(err_reply+8, &temp, 4);
                                returnValue = write(i, err_reply, 12);
                            }
                            break;
                        case LOC_REQUEST_CACHE:
                            temp = 0;
                            memcpy(err_reply, &temp, 4);
                            if (termination_flag) {
                                temp = LOC_FAILURE;
                                memcpy(err_reply+4, &temp, 4);
                                temp = ERROR_BINDER_SHUTTING_DOWN;
                                memcpy(err_reply+8, &temp, 4);
                                returnValue = write(i, err_reply, 12);
                                break;
                            }
                            returnValue = read(i,name,64);
                            argTypes = (int *)malloc(sizeof(int) * (msg_length-64));
                            returnValue = read(i,argTypes,msg_length-64);
                            if (returnValue< 0) return ERROR_READ_CLIENT_SOCKET;
                            count = count_server(database, name, argTypes);
                            if (count > 0) {
                                returnValue = write(i, &count, 4);
                                temp = LOC_SUCCESS;
                                returnValue = write(i, &temp, 4);
                                for (struct server_entry *temp = database->head; temp; temp = temp->next) {
                                    for (struct func_entry *f = temp->head; f; f = f->next) {
                                        struct func_entry f2;
                                        memcpy(f2.name, name, 64);
                                        f2.argTypes = argTypes;
                                        if (cmp_functions(f, &f2)) {
                                            returnValue = write(i, temp->hostname, 256);
                                            returnValue = write(i, &(temp->port), 4);
                                        }
                                    }
                                }
                            } else {
                                temp = LOC_FAILURE;
                                memcpy(err_reply+4, &temp, 4);
                                temp = ERROR_NO_AVAILABLE_SERVER;
                                memcpy(err_reply+8, &temp, 4);
                                returnValue = write(i, err_reply, 12);
                                if (returnValue < 0) return ERROR_WRITE_CLIENT_SOCKET;
                            }
                            break;
                        case TERMINATE_ACK:
                            printf("received ack\n");
                            terminated_servers++;
                            if (terminated_servers == active_servers) {
                                //all servers have terminated
                                free_db(database);
                                printf("Binder is shutting down\n");
                                close(binderSocket);
                                return 0;
                            }
                            break;
                        case TERMINATE:
                            printf("received termination msg\n");
                            termination_flag = 1;
                            for (struct server_entry *temp_s = database->head; temp_s; temp_s = temp_s->next) {
                                struct hostent *server;
                                struct sockaddr_in server_addr;
                                int b2s_Socket = socket(AF_INET, SOCK_STREAM, 0);
                                if (b2s_Socket < 0) perror("ERROR opening socket");
                                server = gethostbyname(temp_s->hostname);
                                if (server == NULL) {
                                    fprintf(stderr,"ERROR, no such host\n");
                                }
                                bzero((char *) &server_addr, sizeof(server_addr));
                                server_addr.sin_family = AF_INET;
                                bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
                                server_addr.sin_port = htons(temp_s->port);
                                if (connect(b2s_Socket,(struct sockaddr *) &server_addr,sizeof(server_addr)) < 0) {
                                    continue;
                                }
                                //connected
                                active_servers++;
                                char msg[8];
                                temp = 0;
                                memcpy(msg, &temp, 4);
                                int msgType = TERMINATE;
                                memcpy(msg+4, &msgType, 4);
                                returnValue = write(b2s_Socket,msg,8);
                                if (returnValue < 0) perror("ERROR writing to socket");
                            }
                            if (active_servers == 0) {
                                free_db(database);
                                printf("Binder is shutting down\n");
                                close(binderSocket);
                                return 0;
                            }
                            break;
                        default:
                            printf("Unknown msg type\n");
                            break;
                    }
                }
            }
        }
    }
}

