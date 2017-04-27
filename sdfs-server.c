
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

/* glib provides additional data structures
 *   and logging framework https://developer.gnome.org/glib/ */
#include <glib.h>

/* libconfuse provides support for using a configuration file
 * https://github.com/martinh/libconfuse */
#include <confuse.h>

#include "sdfs.h"
#include "network/tcp.h"
#include "crypto/encrypt.h"
#include "crypto/mac.h"
#include "crypto/tls.h"
#include "output/console.h"

// use control char as delimiter in composite strings
#define STRING_DELIM "\x7f"


int debug, option;
gboolean has_valid_certs = TRUE;
gboolean client_authenticated, exit_requested = FALSE;
uint16_t port = 55555;
char *progname = "";
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
void server_exit(int exit_code) {

    exit_requested = TRUE;
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

    printf("SDFS Server exit.\n");
    exit(exit_code);

}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void server_display_usage(void) {
    printf("Usage:\n");
    printf("%s [-p <port>] [-d]\n", progname);
    printf("%s -h\n", progname);
    printf("\n");
    printf("-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
    printf("-d: outputs debug information while running\n");
    printf("-h: prints this help text\n\n");
    server_exit(1);
}


/**************************************************************************
 * Read from configuration file                                            *
 *                                                                         *
 ***************************************************************************/
void server_parse_configuration(void) {
    // specify configuration filename
    GString *config_filename = g_string_new("config/sdfs-server.conf");

    // Create array of cfg_opt_t structs listing the configuration parameters
    // that will be read from the configuration file. For each parameter a default value
    // is specified if it cannot be read from the configuration file.
    cfg_opt_t configParameters[] =
            {
                    CFG_INT("default_service_port", 55555, CFGF_NONE),
                    CFG_STR("default_host_cert_name", "", CFGF_NONE),
                    CFG_STR("default_host_priv_key_name", "", CFGF_NONE),
                    CFG_STR("default_ca_cert_name", "", CFGF_NONE),
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
    cert = cfg_getstr(configuration, "default_host_cert_name");
    ca_cert = cfg_getstr(configuration, "default_ca_cert_name");
    priv_key = cfg_getstr(configuration, "default_host_priv_key_name");

    // display strings loaded from config file
    printf("\nParsing configuration file \"%s\"\n", config_filename->str);
    printf("---------------------------------------------------\n");
    printf("--default SDFS server port: %i\n", port);
    printf("--default host cert name: %s\n", cert);
    printf("--default host priv key name: %s\n", priv_key);
    printf("--default ca cert name: %s\n", ca_cert);
}

/**************************************************************************
 * Parse the command line parameters                                       *
 *                                                                         *
 ***************************************************************************/
void server_parse_commandline_parameters(int argc, char *argv[]) {

    printf("\nParsing parameters specified on command line\n");
    printf("--------------------------------------------\n");
    printf("Command line parameters are optional and will override\n");
    printf("configuration file parameters listed above.\n");
    int option_count = argc;
    /* Check command line options */
    while((option = getopt(argc, argv, "p:hd")) > 0){
        switch(option) {
            case 'd':
                debug = 1;
                printf("--debug mode: on\n");
                break;
            case 'h':
                server_display_usage();
                break;
            case 'p':
                port = atoi(optarg);
                printf("--port used to listen for TLS connections from clients: %i\n", port);
                break;
            default:
                g_error("Unknown option %c\n", option);
                server_display_usage();
        }
    }
    argv += optind;
    argc -= optind;

    if(argc > 0){
        g_error("Too many options!\n");
        server_display_usage();
    }

    if (option_count == 1) {
        printf("--No command line parameters were specified\n\n");
    }
    else {
        printf("\n");
    }

}

void server_process_traffic() {

    int maxfd, result;
    /* only using one file descriptor but useing seclect so we can add additional channel if needed */
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

        // add any network sockets to the fd_set
        FD_SET(tcp_net_fd, &rd_set);

        // this select() blocks until there is activity on one of the sockets in the set
        activity = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
        // check for errors
        if (activity < 0 && errno == EINTR) {
            continue;
        }
        if (activity < 0) {
            perror("select()");
            server_exit(1);
        }

        // check if the activity was TCP tunnel control on the network device
        if (FD_ISSET(tcp_net_fd, &rd_set)) {

            //got data: read it
            result = read_from_tls(&buffer_in);
            if (result == 1) {
                server_exit(1);
            }
            //printf("TLS read %d bytes\n", buffer_in.size);

        }

    }
}

void server_process_signal (int signal) {

    //exit on interrupt signal
    if (signal == SIGINT) {
        server_exit(0);
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
    printf("SDFS Server Launched\n");
    printf("********************\n");

    // Read configuration from config file
    server_parse_configuration();

    // Parse command line options
    server_parse_commandline_parameters(argc, argv);

    // safely handle interrupt signals
    signal(SIGINT, server_process_signal);

    // initialize TLS for control channel
    initialize_tls(ca_cert,cert, priv_key, TRUE);

    // create socket for tcp channel
    result = create_tcp_socket();
    if (result == 1) {
        server_exit(1);
    }

    // create listening tcp socket
    // and wait to accept() client connection
    result = listen_for_tcp_connections();
    if (result == 1) {
        server_exit(1);
    }

    // create tls session by waiting for ssl_accept()
    result = accept_tls_connections();
    if (result == 1) {
        server_exit(1);
    }

    server_process_traffic();

    server_exit(0);
}
