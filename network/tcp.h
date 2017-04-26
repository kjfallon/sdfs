
#ifndef SDFS_TCP_H_H
#define SDFS_TCP_H_H

int create_tcp_socket(void);
int listen_for_tcp_connections(void);
int connect_tcp_to_remote_server(void);

#endif //SDFS_TCP_H_H