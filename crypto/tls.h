#ifndef SDFS_TLS_H
#define SDFS_TLS_H

#include "encrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <glib/gtypes.h>
#include <glib/gmessages.h>
#include <shadow.h>
#include <crypt.h>

#include "../output/console.h"
#include "pki.h"

int initialize_tls(char *ca_cert, char *cert, char *priv_key);
int accept_tls_connections();
int connect_to_tls();
int write_to_tls(BufferObject *buffer);
int read_from_tls(BufferObject *buffer);
int validate_client_credentials(char *username, char *password);


#endif //SDFS_TLS_H
