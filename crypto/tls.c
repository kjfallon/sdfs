#include "tls.h"
#include "../sdfs.h"
#include "encrypt.h"

#define CHAR_DELIM   '\x7f'
#define STRING_DELIM "\x7f"

extern SSL_CTX     *ssl_ctx;
extern SSL         *ssl;
extern gboolean has_valid_certs, userA_authenticated, userB_authenticated;
extern int tcp_net_fd;
extern unsigned char session_encryption_key[KEY_SIZE];
extern unsigned char session_hmac_key[IV_SIZE];
extern unsigned char current_nonce[NONCE_SIZE];
extern char *remote_hostname;
extern char *mode_of_operation;

/***************************************************************************
 * Create SSL context                                                      *
 *                                                                         *
 ***************************************************************************/
int initialize_tls( char *ca_cert, char *cert, char *priv_key, gboolean is_server) {



    // register error strings
    SSL_load_error_strings();
    // register the available SSL/TLS ciphers and digests
    SSL_library_init();
    // seed the random number generator from /dev/urandom
    RAND_poll();

    // Specify to use TLS (as opposed to SSL v2 or v3)
    if (is_server == TRUE) {
        ssl_ctx = SSL_CTX_new(TLSv1_2_server_method());
    }
    else {
        ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
    }


    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    // load CA signing certificate
    if (SSL_CTX_load_verify_locations(ssl_ctx, ca_cert, NULL) != 1) {
        has_valid_certs == FALSE;
        perror("TLS: Unable to load CA certificate");
        syslog (LOG_ERR, "ERROR: TLS: Unable to load CA certificate");
        return 1;
    }

    // load certificate
    if (SSL_CTX_use_certificate_file(ssl_ctx, cert, SSL_FILETYPE_PEM) != 1) {
        has_valid_certs == FALSE;
        perror("TLS: Unable to load certificate");
        syslog (LOG_ERR, "ERROR: TLS: Unable to load certificate");
        return 1;
    }
    // load private key
    if (SSL_CTX_use_PrivateKey_file (ssl_ctx, priv_key, SSL_FILETYPE_PEM) != 1) {
        has_valid_certs == FALSE;
        perror("TLS: Unable to load private key");
        syslog (LOG_ERR, "ERROR: TLS: Unable to load private key");
        return 1;
    }
    // check if this is the private key for the pub key in the cert
    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        has_valid_certs == FALSE;
        perror("TLS: Private key and cert mismatch");
        syslog (LOG_ERR, "ERROR: Private key and cert mismatch");
        return 1;
    }
    else {
        printf("Loaded and validated this host's x509 certificate and key.\n");
        syslog (LOG_INFO, "INFO: Loaded and validated this host's x509 certificate and key.");
    }
    return 0;

}


/***************************************************************************
 * Start listening for TLS connections                                     *
 *                                                                         *
 ***************************************************************************/
int accept_tls_connections() {

    if( !(ssl = SSL_new(ssl_ctx)) ) {
        perror("TLS: error create SSL object");
        syslog (LOG_ERR, "ERROR: TLS: error create SSL object");
        return 1;
    }
    SSL_set_fd(ssl, tcp_net_fd);
    if( SSL_accept(ssl) < 0 )
    {
        perror("TLS: error during SSL_accept()");
        syslog (LOG_ERR, "ERROR: TLS: error create SSL object");
        return 1;
    }
    printf("TLS: channel established using %s %s\n", SSL_get_cipher_version(ssl),SSL_get_cipher_name(ssl));
    syslog (LOG_INFO, "INFO: TLS: channel established using %s %s", SSL_get_cipher_version(ssl),SSL_get_cipher_name(ssl));

    return 0;
}

/***************************************************************************
 * Write message to TLS channel                                            *
 *                                                                         *
 ***************************************************************************/
int write_message_to_tls(BufferObject *buffer, uint8_t message_type) {

    // message = type + data
    BufferObject message;
    memcpy(&message.data[0],&message_type, 1);
    memcpy(&message.data[1],&buffer->data[0], buffer->size);
    message.size = buffer->size + 1;

    // write buffer to ssl channel
    if( (SSL_write(ssl, (uint8_t *)&message.data, message.size)) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    switch (message_type) {
        case HELLO:
            printf("%s: wrote message HELLO %d bytes\n", mode_of_operation, (int)message.size );
            syslog (LOG_INFO, "INFO: %s: wrote message HELLO %d bytes", mode_of_operation, (int)message.size );
            break;
        case OK:
            printf("%s: wrote message OK %d bytes\n", mode_of_operation, (int)message.size );
            syslog (LOG_INFO, "INFO: %s: wrote message OK %d bytes", mode_of_operation, (int)message.size );
            break;
        case LOGIN:
            printf("%s: wrote message LOGIN %d bytes\n", mode_of_operation, (int)message.size );
            syslog (LOG_INFO, "INFO: %s: wrote message LOGIN %d bytes", mode_of_operation, (int)message.size );
            break;
        case LOGOUT:
            printf("%s: wrote message LOGOUT %d bytes\n", mode_of_operation, (int)message.size );
            syslog (LOG_INFO, "INFO: %s: wrote message LOGOUT %d bytes", mode_of_operation, (int)message.size );
            break;
        case SET_PERM:
            printf("%s: wrote message SET_PERM %d bytes\n", mode_of_operation, (int)message.size );
            syslog (LOG_INFO, "INFO: %s: wrote message SET_PERM %d bytes", mode_of_operation, (int)message.size );
            break;
        case DELEGATE_PERM:
            printf("%s: wrote message DELEGATE_PERM %d bytes\n", mode_of_operation, (int)message.size );
            syslog (LOG_INFO, "INFO: %s: wrote message DELEGATE_PERM %d bytes", mode_of_operation, (int)message.size );
            break;
        case GET_FILE:
            printf("%s: wrote message GET_FILE %d bytes\n", mode_of_operation, (int)message.size );
            syslog (LOG_INFO, "INFO: %s: wrote message GET_FILE %d bytes", mode_of_operation, (int)message.size );
            break;
        case FILE_DATA:
            printf("%s: wrote message FILE_DATA %d bytes\n", mode_of_operation, (int)message.size );
            syslog (LOG_INFO, "INFO: %s: wrote message FILE_DATA %d bytes", mode_of_operation, (int)message.size );
            break;
        case BAD_COMMAND:
            printf("%s: wrote message BAD_COMMAND %d bytes\n", mode_of_operation, (int)message.size );
            syslog (LOG_INFO, "INFO: %s: wrote message BAD_COMMAND %d bytes", mode_of_operation, (int)message.size );
            break;
        case QUIT:
            printf("%s: wrote message QUIT %d bytes\n", mode_of_operation, (int)message.size );
            syslog (LOG_INFO, "INFO: %s: wrote message QUIT %d bytes", mode_of_operation, (int)message.size );
            break;

    }

    return 0;

}

/***************************************************************************
 * Read message from TLS channel                                           *
 *                                                                         *
 ***************************************************************************/
int read_from_tls(BufferObject *buffer) {

    // read data from ssl control channel
    if( (buffer->size = SSL_read(ssl, (uint8_t*)&buffer->data, BUFSIZE)) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("TLS: read %d bytes from channel: ", (int)buffer->size);
    hexPrint(buffer->data, buffer->size);

    // Extract the message type from the buffer of bytes sent over TLS
    // this allows us to know what to do with the rest of the bytes
    uint8_t message_type;
    message_type = buffer->data[0];

    // Extract the message payload from the buffer
    BufferObject message;
    message.size = buffer->size - 1;
    memcpy(&message.data[0], &buffer->data[1], message.size);
    //printf("Message type: ");
    //printf("%02x\n", message_type);

    int result;
    BufferObject reply;
    memcpy(&reply.data[0],&STRING_DELIM, 1);
    reply.size = 1;

    switch (message_type) {
        case HELLO:
            printf("%s: received message HELLO\n", mode_of_operation);
            syslog (LOG_INFO, "INFO: %s: received message HELLO", mode_of_operation);
                   break;
        case OK:
            printf("%s: received message OK\n", mode_of_operation);
            syslog (LOG_INFO, "INFO: %s: received message OK", mode_of_operation);
            break;
        case LOGIN:
            printf("%s: received message LOGIN\n", mode_of_operation);
            syslog (LOG_INFO, "INFO: %s: received message LOGIN", mode_of_operation);
            //process authentication
            result = validate_client_credentials(&message);
            // notify client of result
            if (result == 0) {
                write_message_to_tls(&reply, OK);
            }
            else {
                write_message_to_tls(&reply, BAD_COMMAND);
            }
            break;
        case LOGOUT:
            printf("%s: received message LOGOUT\n", mode_of_operation);
            syslog (LOG_INFO, "INFO: %s: received message LOGOUT", mode_of_operation);
            //process logout
            result = logout_authenticated_user(&message);
            // notify client of result
            if (result == 0) {
                write_message_to_tls(&reply, OK);
            }
            else {
                write_message_to_tls(&reply, BAD_COMMAND);
            }
            break;
        case SET_PERM:
            printf("%s: received message SET_PERM\n", mode_of_operation);
            syslog (LOG_INFO, "INFO: %s: received message SET_PERM", mode_of_operation);
            write_message_to_tls(&reply, NOT_IMPLEMENTED);
            break;
        case DELEGATE_PERM:
            printf("%s: received message DELEGATE_PERM\n", mode_of_operation);
            syslog (LOG_INFO, "INFO: %s: received message DELEGATE_PERM", mode_of_operation);
            write_message_to_tls(&reply, NOT_IMPLEMENTED);
            break;
        case GET_FILE:
            printf("%s: received message GET_FILE\n", mode_of_operation);
            syslog (LOG_INFO, "INFO: %s: received message GET_FILE", mode_of_operation);
            write_message_to_tls(&reply, NOT_IMPLEMENTED);
            break;
        case BAD_COMMAND:
            printf("%s: received message BAD_COMMAND\n", mode_of_operation);
            syslog (LOG_INFO, "INFO: %s: received message BAD_COMMAND", mode_of_operation);
            break;
        case NOT_IMPLEMENTED:
            printf("%s: received message NOT_IMPLEMENTED\n", mode_of_operation);
            syslog (LOG_INFO, "INFO: %s: received message NOT_IMPLEMENTED", mode_of_operation);
            break;
        case QUIT:
            printf("%s: received message QUIT\n", mode_of_operation);
            syslog (LOG_INFO, "INFO: %s: received message QUIT", mode_of_operation);
            return 1;

    }

    return 0;

}

/***************************************************************************
 * Do not construct a message just send bytes                              *
 *                                                                         *
 ***************************************************************************/
int write_bytes_to_tls(BufferObject *buffer) {



    // write buffer to ssl control channel
    if( (SSL_write(ssl, (uint8_t *)&buffer->data, buffer->size)) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf( "TLS: wrote %d bytes\n", (int)buffer->size );
    syslog (LOG_INFO, "INFO: TLS: wrote %d bytes", (int)buffer->size );
    hexPrint(buffer->data, buffer->size);

    return 0;

}

/***************************************************************************
 * Connect to TLS server and verify server certificate                     *
 *                                                                         *
 ***************************************************************************/
int connect_to_tls() {


    if( !(ssl = SSL_new(ssl_ctx)) ) {
        perror("TLS: error create SSL object");
        syslog (LOG_ERR, "ERROR: TLS: error create SSL object");
        return 1;
    }

    SSL_set_fd(ssl, tcp_net_fd);
    if( SSL_connect(ssl) < 0 )
    {
        perror("TLS: error during SSL_connect()");
        syslog (LOG_ERR, "ERROR: TLS: error during SSL connect()");
        return 1;
    }

    X509 *server_cert = SSL_get_peer_certificate(ssl);
    // Did we get a server cert?
    if (server_cert == NULL) {
        // missing server cert
        syslog (LOG_ERR, "ERROR: TLS: server certificate missing");
        return 1;
    }

    char *cert_subject_cn;
    cert_subject_cn = tls_text_name(X509_get_subject_name(server_cert), NID_commonName);

    // Verify the signature of the server cert
     int v_result = SSL_get_verify_result(ssl);
        if (v_result == X509_V_OK) {
            // server cert signature is correct
            syslog (LOG_INFO, "INFO: TLS: server certificate was signed by a trusted CA");
        } else {
            // server cert signature is not correct
            syslog (LOG_ERR, "ERROR: TLS: server certificate was NOT signed by a trusted CA");
            g_warning("TLS: server cert '%s' was not signed by a trusted CA\n", cert_subject_cn);
            return 1;
        }

    // verify that the server cert CN matches the CN of the hostname the client specified
    gboolean matched = FALSE;
    if (cert_subject_cn && *cert_subject_cn) {
        matched = match_hostname(cert_subject_cn, remote_hostname);
        if (! matched) {
            g_warning("TLS: server CN '%s' does not match host name '%s\n'", cert_subject_cn, remote_hostname);
            syslog (LOG_ERR, "ERROR: TLS:  server CN '%s' does not match host name '%s'", cert_subject_cn, remote_hostname);
            return 1;
        }
    } else {
        g_warning("TLS: server certificate missing common name\n");
        syslog (LOG_ERR, "ERROR: TLS: server certificate missing common name");

        return 1;
    }

    printf("TLS: channel established using %s %s\n", SSL_get_cipher_version(ssl),SSL_get_cipher_name(ssl));
    syslog (LOG_INFO, "INFO: TLS: channel established using %s %s\n", SSL_get_cipher_version(ssl),SSL_get_cipher_name(ssl));
    printf("TLS: SERVER AUTH OK, server DNS hostname (%s) matches cert CN (%s)\n", remote_hostname, cert_subject_cn);
    syslog (LOG_INFO, "INFO: TLS: SERVER AUTH OK, server DNS hostname (%s) matches cert CN (%s)\n", remote_hostname, cert_subject_cn);

    return 0;
}

/***************************************************************************
 * Validate credentials of TLS client                                      *
 *                                                                         *
 ***************************************************************************/
int validate_client_credentials(BufferObject *message) {

    /* extract username and password from payload */
    int i;
    int delim_location;
    for( i=0; message->data[i]; ++i )
        if( message->data[i] == CHAR_DELIM )
        {
            delim_location = i;
            break;
        }

    int username_length = delim_location;
    int password_length = (message->size - delim_location) - 1;
    char username[username_length + 1];
    char password[password_length + 1];

    memcpy(&username[0],&message->data[0], username_length);
    username[username_length] = '\0';
    printf("SERVER: received client auth username: %s\n", username);
    syslog (LOG_INFO, "INFO: SERVER: received client auth username");

    memcpy(&password[0],&message->data[username_length + 1], password_length);
    password[password_length] = '\0';
    printf("SERVER: received client auth password: %s\n", password);
    syslog (LOG_INFO, "INFO: SERVER: received client auth password");

    // pull shadow password for the user from the system
    struct spwd *shadow_password;
    shadow_password = getspnam(username);
    //printf("TLS: shadow: %s\n", shadow_password->sp_pwdp);

    // calculate the hash of the supplied password
    char *password_hash;
    password_hash = crypt(password, shadow_password->sp_pwdp);
    //printf("TLS: hash: %s\n", password_hash);

    if( strcmp(password_hash, shadow_password->sp_pwdp) == 0 ) {
        printf("SERVER: CLIENT AUTH OK, client credentials match local OS user\n");
        syslog (LOG_INFO, "INFO: SERVER: CLIENT AUTH OK, client credentials match local OS user");
        if (strcmp(username, "userA") == 0) {
            userA_authenticated = TRUE;
            syslog (LOG_INFO, "INFO: SERVER: userA logged in");
        }
        else if (strcmp(username, "userB") == 0) {
            userB_authenticated = TRUE;
            syslog (LOG_INFO, "INFO: SERVER: userB logged in");
        }
    }
    else {
        printf("SERVER: client auth failed\n");
        return 1;
    }

    return 0;
}

/***************************************************************************
 * Log out an authenticated user                                           *
 *                                                                         *
 ***************************************************************************/
int logout_authenticated_user(BufferObject *message) {

    /* extract username from payload */
    int username_length = message->size;
    char username[username_length + 1];

    memcpy(&username[0],&message->data[0], username_length);
    username[username_length] = '\0';
    printf("SERVER: received logout request for username: %s\n", username);
    syslog (LOG_INFO, "INFO: SERVER: received logout request for username: %s\n", username);

    if ((strcmp(username, "userA") == 0) && (userA_authenticated == TRUE) )  {
        userA_authenticated == FALSE;
        printf("SERVER: userA logged out\n");
        syslog (LOG_INFO, "INFO: SERVER: userA logged out");
    }
    else if ((strcmp(username, "userB") == 0) && (userB_authenticated = TRUE) ) {
        userB_authenticated == FALSE;
        printf("TLS: userB logged out\n");
        syslog (LOG_INFO, "INFO: SERVER: userB logged out");
    }
    else {
        printf("TLS: Either invalid user or not logged in\n");
        syslog (LOG_ERR, "INFO: SERVER: Either invalid user or not logged in");
        return 1;
    }

    return 0;
}
