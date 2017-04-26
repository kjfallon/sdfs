
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "tcp.h"
#include "dns.h"

extern int optval, tcp_net_fd, tcp_sock_fd;
extern struct sockaddr_in local, remote;
extern uint16_t port;
extern socklen_t remotelen;
extern char *remote_hostname;

#define LISTEN_QUEUE_MAX 20

/***************************************************************************
 * Create socket for tcp tunnel                                            *
 *                                                                         *
 ***************************************************************************/
int create_tcp_socket(void) {


    if ( (tcp_sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("creating tcp socket()");
        return 1;
    }
    //printf("Successfully created tcp socket\n");
    return 0;
}

/***************************************************************************
 * Listen for tcp tunnel connections from clients                          *
 *                                                                         *
 ***************************************************************************/
int listen_for_tcp_connections(void) {

    /* avoid EADDRINUSE error on bind() */
    // set options on socket descriptor
    if(setsockopt(tcp_sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
        perror("setsockopt()");
        return 1;
    }
    // create local address object and bind socket descriptor to it
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(tcp_sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
        perror("tcp bind error bind()");
        return 1;
    }

    if(listen(tcp_sock_fd, LISTEN_QUEUE_MAX) < 0 ) {
        perror("tcp listen error listen()");
        return 1;
    }
    //printf("Successfully created listening tcp socket %s:%i\n", inet_ntoa(local.sin_addr), port);
    printf("Listening for client TLS connections on %s:%i\n", inet_ntoa(local.sin_addr), port);

    /* wait for connection request */
    remotelen = sizeof(remote);
    memset(&remote, 0, remotelen);
    if ((tcp_net_fd = accept(tcp_sock_fd, (struct sockaddr*)&remote, &remotelen)) < 0){
        perror("accept()");
        return 1;
    }
    printf("Client connected from %s\n", inet_ntoa(remote.sin_addr));

    return 0;
}

/***************************************************************************
 * Connect tcp to remote server                              *
 *                                                                         *
 ***************************************************************************/
int connect_tcp_to_remote_server(void) {

    /* assign the destination address */
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    int result = dns_lookup(remote_hostname);
    if (result == 1) {
        return 1;
    }
    //remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);
    printf("CLIENT: connecting to server %s\n", inet_ntoa(remote.sin_addr));
    if (connect(tcp_sock_fd, (struct sockaddr*) &remote, sizeof(remote))) {
        perror("failure tcp to remote connect()");
        return 1;
    }
    tcp_net_fd = tcp_sock_fd;
    printf("CLIENT: Ready to use tcp transport to server %s\n", inet_ntoa(remote.sin_addr));

    return 0;
}

