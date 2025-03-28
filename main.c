/*
 *The executable Listener from the project Over-TCP Protocols Debugger
 *Copyright (C) 2025  John Doe

 *This program is free software: you can redistribute it and/or modify
 *it under the terms of the GNU General Public License as published by
 *the Free Software Foundation, version 3 of the License, GPL-3.0-only.

 *This program is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 *MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *GNU General Public License for more details.

 *You should have received a copy of the GNU General Public License
 *along with this program.  If not, see <https://www.gnu.org/licenses/>
*/
#define _LISTENER_SOURCE
#include <argp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#define SERVER_SOCKET_ERROR -1
#define SERVER_SETSOCKOPT_ERROR -2
#define SERVER_BIND_ERROR -3
#define SERVER_LISTEN_ERROR -4
#define STDIN_READ_ERROR -5
#define CLIENT_RESOLVE_ERROR -6
#define WRITE_SOCKET_ERROR -7
#define WRITE_STDOUT_ERROR -8
#define SOCKET_READ_ERROR -9
#define HEAP_BUFFER_OVERFLOWED -10
#define DATA_SECTION_OVEFLOWED -11
#define INVALID_POINTER -12

#define BUF_SIZE 65536

typedef enum {TRUE = 1, FALSE = 0} const bool;

const char *arpg_program_version = "Listener 1.0";
const char *argp_program_bug_address = "me, John Doe, you know how! ;)";
struct arguments{
    char *bind_addr;
    int local_port;
};
static const struct argp_option options[] =
{
    {"bind_addr", 'b', "BIND_ADDR", 0, "Local address to bind this listener",0},
    {"local_port", 'l', "LOCAL_PORT", 0, "Local port the bind address listen to",0},
    {0}
};
static error_t parse_opt(int key, char* arg, struct argp_state *state){
    struct arguments *arguments = state->input;
    switch(key){
        case 'b':
            if (arguments->bind_addr != NULL){
                free(arguments->bind_addr);
            }
            arguments->bind_addr=(char*)malloc(40*sizeof(char));
            if (arguments->bind_addr == NULL){
                exit(ARGP_ERR_UNKNOWN);
            }
            strncpy(arguments->bind_addr,arg,40);
            break;
        case 'l':
            if (atoi(arg)>=0 && atoi(arg) < 65536){
                arguments->local_port = atoi(arg);
                break;
            }else{
                exit(ARGP_ERR_UNKNOWN);
            }

        case ARGP_KEY_END:
            if (arguments->local_port == 0){
                argp_failure(state, -10, 1, "required -l See --help for more information");
                exit(ARGP_ERR_UNKNOWN);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const char doc[] = "Listener -- A program to listen to data receive from client.\nFrom me, John Doe. ;)";
static const struct argp argp = {options, parse_opt,0,doc,0,0,0};
struct arguments arguments;

int check_ipversion(char * address);
void closeSockets();
size_t convert_ssize_to_size(ssize_t value);
int createListenerSocket(int port);
void forward_data(int source_sock);
void handle_client(int client_sock);
void listenerLoop();
void printMessage(const char *format, ...);
void sigchld_handler();
void sigterm_handler();

int server_sock,client_sock = 0;
int connections_processed = 0;

#define BACKLOG 20 // how many pending connections queue will hold

int main(int argc, char *argv[])
{
    arguments.bind_addr = NULL;
    arguments.local_port = 0;
    argp_parse(&argp, argc, argv, ARGP_NO_ARGS, 0, &arguments);

    if ((server_sock = createListenerSocket(arguments.local_port)) < 0) { // start server
        printMessage("Cannot run server: %m");
        return server_sock;
    }

    signal(SIGCHLD, sigchld_handler); // prevent ended children from becoming zombies
    signal(SIGTERM, sigterm_handler); // handle KILL signal

    listenerLoop();

}

int check_ipversion(char * address)
{
/* Check for valid IPv4 or Iv6 string. Returns AF_INET for IPv4, AF_INET6 for IPv6 */

    struct in6_addr bindaddr;

    if (inet_pton(AF_INET, address, &bindaddr) == 1) {
         return AF_INET;
    } else {
        if (inet_pton(AF_INET6, address, &bindaddr) == 1) {
            return AF_INET6;
        }
    }
    return 0;
}

int createListenerSocket(int port){
    int server_sock, optval = 1;
    int validfamily=0;
    struct addrinfo hints, *res=NULL;
    char *portstr=NULL;
    portstr = (char*)malloc(12*sizeof(char));
    if (portstr == NULL){
        printMessage("invalid port pointer");
        exit(INVALID_POINTER);
    }
    memset(&hints, 0x00, sizeof(hints));
    server_sock = -1;

    hints.ai_flags    = AI_NUMERICSERV;   /* numeric service number, not resolve */
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    /* prepare to bind on specified numeric address */
    if (arguments.bind_addr != NULL) {
        /* check for numeric IP to specify IPv6 or IPv4 socket */
        if ((validfamily = check_ipversion(arguments.bind_addr))) {
             hints.ai_family = validfamily;
             hints.ai_flags |= AI_NUMERICHOST; /* bind_addr is a valid numeric ip, skip resolve */
        }
    } else {
        /* if bind_address is NULL, will bind to IPv6 wildcard */
        hints.ai_family = AF_INET; /* Specify IPv6 socket, also allow ipv4 clients */
        hints.ai_flags |= AI_PASSIVE; /* Wildcard address */
    }

    sprintf(portstr, "%d", port);

    /* Check if specified socket is valid. Try to resolve address if bind_address is a hostname */
    if (getaddrinfo(arguments.bind_addr, portstr, &hints, &res) != 0) {
        return CLIENT_RESOLVE_ERROR;
    }

    if ((server_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
        freeaddrinfo(res); // Free memory on failure
        return SERVER_SOCKET_ERROR;
    }

    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        freeaddrinfo(res);
        return SERVER_SETSOCKOPT_ERROR;
    }

    if (bind(server_sock, res->ai_addr, res->ai_addrlen) == -1) {
        close(server_sock);
        freeaddrinfo(res);
        return SERVER_BIND_ERROR;
    }

    if (listen(server_sock, BACKLOG) < 0) {
        close(server_sock);
        freeaddrinfo(res);
        return SERVER_LISTEN_ERROR;
    }

    if (res != NULL) {
        freeaddrinfo(res);
    }
    if (portstr != NULL){
        free(portstr);
    }
    if (arguments.bind_addr != NULL){
        free(arguments.bind_addr);
    }
    return server_sock;
}

void printMessage(const char *format,...){
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr,format,ap);
    fprintf(stderr,"\n");
    va_end(ap);
}

/* Handle finished child process */
void sigchld_handler() {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

/* Handle term signal */
void sigterm_handler() {
    close(client_sock);
    close(server_sock);
    exit(0);
}

void listenerLoop() {
    struct sockaddr_storage client_addr;
    socklen_t addrlen = sizeof(client_addr);

    while (TRUE) {
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addrlen);
        if (fork() == 0) { // handle client connection in a separate process
            close(server_sock);
            handle_client(client_sock);
            exit(0);
        } else {
            if (connections_processed < INT_MAX){
                connections_processed++;
            }else{
                printMessage("Data section overflowed");
                exit(DATA_SECTION_OVEFLOWED);
            }
        }
        close(client_sock);
    }
}

void handle_client(int client_sock)
{

    if (fork() == 0) { // a process forwarding(managing) data from client
        forward_data(client_sock);
        exit(0);
    }

    closeSockets();

}

void closeSockets(){
    close(client_sock);
}

void forward_data(int source_sock) {
    ssize_t n;
    size_t m;
    int count = 0;
    char *buffer = NULL;
    buffer = (char*)malloc(BUF_SIZE*sizeof(char));
    if (buffer == NULL){
        printMessage("invalid buffer pointer");
        exit(INVALID_POINTER);
    }
    fd_set fds_receive;    // set of file descriptors
    char *bufferInput = NULL;
    bufferInput = (char*)malloc(BUF_SIZE*sizeof(char));
    if (bufferInput == NULL){
        printMessage("invalid buffer input pointer");
        exit(INVALID_POINTER);
    }
    FD_ZERO(&fds_receive); // initialize the set
    while(1){
        FD_SET(source_sock, &fds_receive);  // monitor the socket
        FD_SET(0, &fds_receive);   // monitor stdin

         /* the select system call will return when one of the file
        descriptors that it is monitoring is ready for an I/O operation */
        if (select(FD_SETSIZE, &fds_receive, NULL, NULL, NULL) < 0) {
            printMessage("select");
            break;
        }

        // if new data arrives from stdin
        if (FD_ISSET(0, &fds_receive)) {
            count = read(0, bufferInput, BUF_SIZE);

            if (count < 0) {          // error in the "read" system call
                printMessage("read");
                exit(STDIN_READ_ERROR);
            } else if (count == 0) {  // "Ctrl+D" pressed, stdin receives 0 bytes
                break;

            }

            // send data received in stdin to socket
            if (count >=0 && count < BUF_SIZE){
                bufferInput[count] = '\0';
                if (write(source_sock, bufferInput, strlen(bufferInput)+1) < 0) {
                    printMessage("write");
                    exit(WRITE_SOCKET_ERROR);
                }
            }else{
                printMessage("STDIN heap buffer overflowed");
                exit(HEAP_BUFFER_OVERFLOWED);
            }

        }

        // if new data arrives from the socket
        if (FD_ISSET(source_sock, &fds_receive)) {
            n = read(source_sock, buffer, BUF_SIZE);

            if (n < 0) {         // error in the "read" system call
                printMessage("read");
                exit(SOCKET_READ_ERROR);
            } else if (n == 0) { // connection terminated, no problem
                break;
            }

            // do stuff with data that arrived from the socket
            if (n >= 0 && n < BUF_SIZE){
                buffer[n] = '\0';
                m = convert_ssize_to_size(n);
                if(fwrite(buffer,1,strlen(buffer)+1,stdout) < m){
                    printMessage("write");
                    exit(WRITE_STDOUT_ERROR);
                }
            }else{
                printMessage("STDOUT heap buffer overflowed");
                exit(HEAP_BUFFER_OVERFLOWED);
            }
        }
    }
    printf("close socket\n");
    if (buffer != NULL){
        free(buffer);
    }
    if (bufferInput != NULL){
        free(bufferInput);
    }
    shutdown(source_sock, SHUT_RDWR); // stop other processes from using socket
    close(source_sock);
}

size_t convert_ssize_to_size(ssize_t value){
    if (value < 0) {
        // Handle negative value appropriately
        // Here, we choose to return 0, but this could be an error code or another handling mechanism
        return 0; // Or handle it as needed
    }
    return (size_t)value; // Safe to convert
}
