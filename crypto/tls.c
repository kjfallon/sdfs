#include "tls.h"
#include "../sdfs.h"

#define CHAR_DELIM   '\x7f'

extern SSL_CTX     *ssl_ctx;
extern SSL         *ssl;
extern gboolean has_valid_certs;
extern int tcp_net_fd;
extern unsigned char session_encryption_key[KEY_SIZE];
extern unsigned char session_hmac_key[IV_SIZE];
extern char *remote_hostname;
extern gboolean client_authenticated;

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
        ssl_ctx = SSL_CTX_new(TLSv1_server_method());
    }
    else {
        ssl_ctx = SSL_CTX_new(TLSv1_client_method());
    }


    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_load_verify_locations(ssl_ctx, ca_cert, NULL);

    // load certificate
    if (SSL_CTX_use_certificate_file(ssl_ctx, cert, SSL_FILETYPE_PEM) != 1) {
        has_valid_certs == FALSE;
        perror("TLS: Unable to load certificate");
    }
    // load private key
    if (SSL_CTX_use_PrivateKey_file (ssl_ctx, priv_key, SSL_FILETYPE_PEM) != 1) {
        has_valid_certs == FALSE;
        perror("TLS: Unable to load private key");
    }
    // check if this is the private key for the pub key in the cert
    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        has_valid_certs == FALSE;
        perror("TLS: Private key and cert mismatch");
    }
    else {
        printf("Loaded and validated this host's x509 certificate and key.\n");
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
        return 1;
    }
    SSL_set_fd(ssl, tcp_net_fd);
    if( SSL_accept(ssl) < 0 )
    {
        perror("TLS: error during SSL_accept()");
        return 1;
    }
    printf("TLS: channel established using %s %s\n", SSL_get_cipher_version(ssl),SSL_get_cipher_name(ssl));

    return 0;
}

int write_to_tls(BufferObject *buffer, uint8_t message_type) {

    switch (message_type) {
        case HELLO:
        case OK:
        case BAD_NONCE:
        case LOGIN:
        case LOGOUT:
        case SET_PERM:
        case DELEGATE_PERM:
        case GET_FILE:
        case FILE_DATA:
        case BAD_COMMAND:
            break;
    }

    // write buffer to ssl control channel
    if( (SSL_write(ssl, (uint8_t *)&buffer->data, buffer->size)) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf( "TLS: wrote %d bytes\n", buffer->size );

    return 0;

}

int read_from_tls(BufferObject *buffer) {
    // read data from ssl control channel
    if( (buffer->size = SSL_read(ssl, (uint8_t*)&buffer->data, BUFSIZE)) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("TLS: read %d bytes: ", buffer->size);
    hexPrint(buffer->data, buffer->size);

    // process commands
    if (buffer->size == 32) {
        // process keying
        printf("Server: received new encryption keys from client...\n");
        memcpy(&session_encryption_key[0], &buffer->data[0], KEY_SIZE);
        memcpy(&session_hmac_key[0], &buffer->data[KEY_SIZE], KEY_SIZE);
        printf("TLS: received encryption key: ");
        hexPrint(session_encryption_key, KEY_SIZE);
        printf("TLS: received hmac key:       ");
        hexPrint(session_hmac_key, KEY_SIZE);
    }
    else if (buffer->size == 1) {
        printf("Client: Authentication to server failed, exiting\n");
        return 1;
    }
    else {
        //process authentication
        /* extract username and password from payload */
        int i;
        int delim_location;

        for( i=0; buffer->data[i]; ++i )
            if( buffer->data[i] == CHAR_DELIM )
            {
                delim_location = i;
                break;
            }
        int username_length = delim_location;
        int password_length = (buffer->size - delim_location) - 1;
        char username[username_length + 1];
        char supplied_password[password_length + 1];


        memcpy(&username[0],&buffer->data[0], username_length);
        username[username_length] = '\0';
        //printf("TLS: found username %s\n", username);
        memcpy(&supplied_password[0],&buffer->data[username_length + 1], password_length);
        supplied_password[password_length] = '\0';
        //printf("TLS: found password %s\n", supplied_password);

        validate_client_credentials(username, supplied_password);

    }
    return 0;

}

int connect_to_tls() {


    if( !(ssl = SSL_new(ssl_ctx)) ) {
        perror("TLS: error create SSL object");
        return 1;
    }

    SSL_set_fd(ssl, tcp_net_fd);
    if( SSL_connect(ssl) < 0 )
    {
        perror("TLS: error during SSL_connect()");
        return 1;
    }

    // verify that the certificate CN matches the CN of the hostname we are connecting to
    gboolean matched = FALSE;
    X509 *server_cert = SSL_get_peer_certificate(ssl);
    char *cert_subject_cn;
    cert_subject_cn = tls_text_name(X509_get_subject_name(server_cert), NID_commonName);
    if (cert_subject_cn && *cert_subject_cn) {
        matched = match_hostname(cert_subject_cn, remote_hostname);
        if (! matched) {
            g_warning("TLS: server CN '%s' does not match host name '%s\n'", cert_subject_cn, remote_hostname);
            return 1;
        }
    } else {
        g_warning("TLS: server certificate missing common name\n");
        return 1;
    }

    printf("TLS: channel established using %s %s\n", SSL_get_cipher_version(ssl),SSL_get_cipher_name(ssl));
    printf("TLS: SERVER AUTH OK, server hostname %s matches cert hostname %s\n", remote_hostname, cert_subject_cn);

    return 0;
}

int validate_client_credentials(char *username, char *password) {

    printf("TLS: received client auth username: %s\n", username);
    printf("TLS: received client auth password: %s\n", password);

    // pull shadow password for the user from the system
    struct spwd *shadow_password;
    shadow_password = getspnam(username);
    //printf("TLS: shadow: %s\n", shadow_password->sp_pwdp);

    // calculate the hash of the supplied password
    char *password_hash;
    password_hash = crypt(password, shadow_password->sp_pwdp);
    //printf("TLS: hash: %s\n", password_hash);

    if( strcmp(password_hash, shadow_password->sp_pwdp) == 0 ) {
        printf("TLS: CLIENT AUTH OK, client credentials match local user\n");
        client_authenticated = TRUE;
    }
    else {
        printf("TLS: client auth failed\n");
        return 1;
    }

    return 0;
}