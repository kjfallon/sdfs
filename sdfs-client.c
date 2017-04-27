
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

/* glib provides additional data structures and logging framework */
#include <glib.h>
/* libconfuse provides support for using a configuration file */
#include <confuse.h>
#include <openssl/rand.h>

#include "network/tcp.h"
#include "crypto/encrypt.h"
#include "crypto/mac.h"
#include "crypto/tls.h"
#include "output/console.h"

#define LISTEN_QUEUE_MAX 20

// use control char as delimiter in composite strings
#define STRING_DELIM "\x7f"
#define CHAR_DELIM   '\x7f'

int debug, option;
gboolean has_valid_certs = TRUE;
gboolean client_authenticated, exit_requested = FALSE;
uint16_t port = 55555;
char *progname = "";
char *if_name = "";
char *remote_hostname = "";
char *ca_cert, *cert, *priv_key;
char *client_username, *client_password;
int tcp_sock_fd;
struct sockaddr_in local, remote;
int tcp_net_fd, optval = 1;
socklen_t remotelen = sizeof(remote);
unsigned char session_encryption_key[KEY_SIZE];
unsigned char session_hmac_key[KEY_SIZE];
unsigned char cbc_iv[IV_SIZE];

SSL_CTX     *ssl_ctx;
SSL         *ssl;

/**************************************************************************
 * safe_exit: zero key data, close tls session and exit               *
 **************************************************************************/
void client_exit(int exit_code) {

    exit_requested =TRUE;
    // erase keys
    printf("\nErasing keys...\n");
    memset(session_encryption_key, '0', KEY_SIZE);
    memset(session_hmac_key, '0', KEY_SIZE);
    
    // close tls
    if (ssl) {
        printf("TLS: closed\n");
        SSL_shutdown(ssl);
    }
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
    if (ssl) {
        SSL_free(ssl);
    }

    // close listening tcp port
    if (tcp_net_fd) {
        shutdown(tcp_net_fd, SHUT_WR);
        close(tcp_net_fd);
    }

    printf("SDFS Client exit.\n");
    exit(exit_code);

}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void display_usage(void) {
    printf("Usage:\n");
    printf("%s -i <ifacename> [-c <serverName>] [-p <port>] [-d]\n", progname);
    printf("%s -h\n", progname);
    printf("\n");
    printf("-p <port>: port that SDFS Server is listening on, default 55555\n");
    printf("-d: outputs debug information while running\n");
    printf("-h: prints this help text\n\n");
    client_exit(1);
}

/**************************************************************************
 * Read from configuration file                                            *
 *                                                                         *
 ***************************************************************************/
void parse_configuration(void) {
    // specify configuration filename
    GString *config_filename = g_string_new("config/sdfs-client.conf");

    // Create array of cfg_opt_t structs listing the configuration parameters
    // that will be read from the configuration file. For each parameter a default value
    // is specified if it cannot be read from the configuration file.
    cfg_opt_t configParameters[] =
            {
                    CFG_INT("default_service_port", 55555, CFGF_NONE),
                    CFG_STR("default_remote_server", "", CFGF_NONE),
                    CFG_STR("default_host_cert_name", "", CFGF_NONE),
                    CFG_STR("default_host_priv_key_name", "", CFGF_NONE),
                    CFG_STR("default_ca_cert_name", "", CFGF_NONE),
                    CFG_STR("default_client_username", "", CFGF_NONE),
                    CFG_STR("default_client_password", "", CFGF_NONE),
                    CFG_END()
            };

    // parse the the config file and create configuration struct
    cfg_t *configuration;
    configuration = cfg_init(configParameters, CFGF_NONE);
    if(cfg_parse(configuration, config_filename->str) == CFG_PARSE_ERROR) {
        g_error("Error parsing configuration file!\n");
    }

    // read integers from config entries
    port = (unsigned short) cfg_getint(configuration, "default_service_port");

    // create strings from config entries

    remote_hostname = cfg_getstr(configuration, "default_remote_server");
    cert = cfg_getstr(configuration, "default_host_cert_name");
    ca_cert = cfg_getstr(configuration, "default_ca_cert_name");
    priv_key = cfg_getstr(configuration, "default_host_priv_key_name");
    client_username = cfg_getstr(configuration, "default_client_username");
    client_password = cfg_getstr(configuration, "default_client_password");

    // display strings loaded from config file
    printf("\nParsing configuration file \"%s\"\n", config_filename->str);
    printf("---------------------------------------------------\n");
    printf("--default port used by SDFS Server: %i\n", port);
    printf("--default remote server: %s\n", remote_hostname);
    printf("--default client cert name: %s\n", cert);
    printf("--default client priv key name: %s\n", priv_key);
    printf("--default ca cert name: %s\n", ca_cert);
}

/**************************************************************************
 * Parse the command line parameters                                       *
 *                                                                         *
 ***************************************************************************/
void parse_commandline_parameters(int argc, char *argv[]) {

    printf("\nParsing parameters specified on command line\n");
    printf("--------------------------------------------\n");
    printf("Command line parameters are optional and will override\n");
    printf("configuration file parameters listed above.\n");
    int option_count = argc;
    /* Check command line options */
    while((option = getopt(argc, argv, "c:p:hd")) > 0){
        switch(option) {
            case 'd':
                debug = 1;
                printf("--debug mode: on\n");
                break;
            case 'h':
                display_usage();
                break;
            case 'p':
                port = atoi(optarg);
                printf("--port used by SDFS Server: %i\n", port);
                break;
            default:
                g_error("Unknown option %c\n", option);
                display_usage();
        }
    }
    argv += optind;
    argc -= optind;

    if(argc > 0){
        g_error("Too many options!\n");
        display_usage();
    }

    if(*remote_hostname == '\0'){
        g_error("Must specify server hostname!\n");
        display_usage();
    }
    if (option_count == 1) {
        printf("No command line parameters were specified.\n\n");
    }
    else {
        printf("\n");
    }

}



void send_client_credentials() {

    int result;
    BufferObject cred_buffer;
    //printf("TLS: username: %s\n", client_username);
    //printf("TLS: size of username: %d\n", strlen(client_username));
    //printf("TLS: password: %s\n", client_password);
    //printf("TLS: size of password: %d\n",strlen(client_password));

    // copy the username and password into  buffer with a delimiter
    memcpy(&cred_buffer.data[0],&client_username[0], strlen(client_username));
    memcpy(&cred_buffer.data[strlen(client_username)],&STRING_DELIM, 1);
    memcpy(&cred_buffer.data[strlen(client_username) + 1],&client_password[0], strlen(client_password));
    cred_buffer.size = strlen(client_username) + 1 + strlen(client_password);

    printf("TLS: sending client authentication to server (%d bytes total)\n", cred_buffer.size);
    //hexPrint(cred_buffer.data, cred_buffer.size);

    result = write_to_tls(&cred_buffer);
    if (result ==1) {
        client_exit(1);
    }
}

void send_session_encryption_keys() {

    int result;
    BufferObject key_buffer;
    // create random session encryption and hmac keys
    RAND_bytes(session_encryption_key, KEY_SIZE);
    RAND_bytes(session_hmac_key, KEY_SIZE);
    // add the keys to the buffer
    memcpy(&key_buffer.data[0],&session_encryption_key[0], KEY_SIZE);
    memcpy(&key_buffer.data[KEY_SIZE],&session_hmac_key[0], KEY_SIZE);
    key_buffer.size = KEY_SIZE + KEY_SIZE;

    //printf("TLS: keys for udp tunnel...\n");
    printf("TLS: created new encryption key: ");
    hexPrint(session_encryption_key, KEY_SIZE);
    printf("TLS: created new hmac key:       ");
    hexPrint(session_hmac_key,KEY_SIZE);

    printf("TLS: sending keys to server (%d bytes total)\n", key_buffer.size);
    //hexPrint(key_buffer.data, key_buffer.size);

    result = write_to_tls(&key_buffer);
    if (result == 1) {
        client_exit(1);
    }
}

void process_traffic() {

    int maxfd, result;
    /* use select() to handle descriptors */
    maxfd = (maxfd > tcp_net_fd) ? maxfd : tcp_net_fd;

    // activity indicator flag
    int activity;
    // create a fd_set of sockets
    fd_set rd_set;
    // create buffer object for inbound and outbound packets
    BufferObject buffer_in, buffer_out;

    while (exit_requested == FALSE) {
        // empty the set
        FD_ZERO(&rd_set);

        // add network sockets to the fd_set

        FD_SET(tcp_net_fd, &rd_set);

        // this select() blocks until there is activity on one of the sockets in the set
        activity = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
        // check for errors
        if (activity < 0 && errno == EINTR) {
            continue;
        }
        if (activity < 0) {
            perror("select()");
            client_exit(1);
        }

        // check if the activity was TCP tunnel control on the network device
        if (FD_ISSET(tcp_net_fd, &rd_set)) {
            //printf("NET2TAP activity on control channel\n");

            //control data: read it
            result = read_from_tls(&buffer_in);
            if (result ==1) {
                client_exit(1);
            }
            //printf("TLS control channel read %d bytes\n", buffer_in.size);

        }

    }
}

void process_signal (int signal) {

    //exit on interrupt signal
    if (signal == SIGINT) {
        client_exit(0);
    }

}

/**************************************************************************
 * Main                                                                    *
 *                                                                         *
 ***************************************************************************/
int main (int argc, char *argv[]) {

    int result;

    progname = argv[0];
    printf("\n********************\n");
    printf("SDFS Client Launched\n");
    printf("********************\n");

    // Read configuration from config file
    parse_configuration();

    // Parse command line options
    parse_commandline_parameters(argc, argv);

    // safely handle interrupt signals
    signal(SIGINT, process_signal);

    // initialize TLS for control channel
    result = initialize_tls(ca_cert,cert, priv_key, FALSE);
    if (result == 1) {
        client_exit(1);
    }

    // create socket for tcp channel
    result = create_tcp_socket();
    if (result ==1) {
        client_exit(1);
    }

    // create tcp connection to server for control channel
    result = connect_tcp_to_remote_server();
    if (result ==1) {
        client_exit(1);
    }

    // create control channel
    result = connect_to_tls();
    if (result ==1) {
        client_exit(1);
    }

    // authenticate to server over tls control channel
    send_client_credentials();

    process_traffic();

    client_exit(0);
}
