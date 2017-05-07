#ifndef SDFS_TLS_H
#define SDFS_TLS_H

#include "encrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <glib.h>
#include <shadow.h>
#include <crypt.h>

#include "../output/console.h"
#include "pki.h"

int initialize_tls(char *ca_cert, char *cert, char *priv_key, gboolean is_server);
int accept_tls_connections();
int connect_to_tls();
int write_message_to_tls(BufferObject *buffer, uint8_t message_type);
int write_bytes_to_tls(BufferObject *buffer);
int read_from_tls(BufferObject *buffer);
int validate_client_credentials(BufferObject *message);
int logout_authenticated_user(BufferObject *message);
int file_permission_set_owner(BufferObject *message);
int get_file_from_server(BufferObject *message);
int file_delegate_permission_server(BufferObject *message);

#endif //SDFS_TLS_H
