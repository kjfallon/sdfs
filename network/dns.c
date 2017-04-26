
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <netdb.h>

#include "dns.h"

extern struct sockaddr_in remote;

/**************************************************************************
 * usage: performs dns lookup on name                                     *
 **************************************************************************/
int dns_lookup(char *hostname) {

    struct hostent *hostent_array;
    struct in_addr **addr_list;

    if ( (hostent_array = gethostbyname( hostname ) ) == NULL)
    {
        // get the host info
        herror("gethostbyname");
        return 1;
    }

    addr_list = (struct in_addr **)hostent_array->h_addr_list;
    char *ip_string = inet_ntoa(*addr_list[0]);

    // assign lookup results to the remote IP address the client will connect to
    remote.sin_addr.s_addr = inet_addr(ip_string);
    printf("DNS lookup for %s is %s\n", hostname, inet_ntoa(remote.sin_addr));

    return 0;
}