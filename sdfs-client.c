
#include "sdfs.h"

#define LISTEN_QUEUE_MAX 20
// use control char as delimiter in composite strings
#define STRING_DELIM "\x7f"
#define CHAR_DELIM   '\x7f'

int debug, option;
gboolean has_valid_certs = TRUE;
gboolean userA_authenticated, userB_authenticated, exit_requested = FALSE;
uint16_t port = 55555;
char *progname = "";
char *if_name = "";
char *remote_hostname = "";
char *ca_cert, *cert, *priv_key;
char *clientA_username, *clientA_password, *clientB_username, *clientB_password;
int tcp_sock_fd;
struct sockaddr_in local, remote;
int tcp_net_fd, optval = 1;
socklen_t remotelen = sizeof(remote);
unsigned char session_encryption_key[KEY_SIZE];
unsigned char cbc_iv[IV_SIZE];
unsigned char session_hmac_key[KEY_SIZE];
unsigned char current_nonce[NONCE_SIZE];

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
                    CFG_STR("default_clientA_username", "", CFGF_NONE),
                    CFG_STR("default_clientA_password", "", CFGF_NONE),
                    CFG_STR("default_clientB_username", "", CFGF_NONE),
                    CFG_STR("default_clientB_password", "", CFGF_NONE),
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
    clientA_username = cfg_getstr(configuration, "default_clientA_username");
    clientA_password = cfg_getstr(configuration, "default_clientA_password");
    clientB_username = cfg_getstr(configuration, "default_clientB_username");
    clientB_password = cfg_getstr(configuration, "default_clientB_password");

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



void send_client_credentials(char *username) {

    int result;
    BufferObject cred_buffer;

    if (strcmp(username, "userA") == 0) {
        // copy the username and password into  buffer with a delimiter
        memcpy(&cred_buffer.data[0], &clientA_username[0], strlen(clientA_username));
        memcpy(&cred_buffer.data[strlen(clientA_username)], &STRING_DELIM, 1);
        memcpy(&cred_buffer.data[strlen(clientA_username) + 1], &clientA_password[0], strlen(clientA_password));
        cred_buffer.size = strlen(clientA_username) + 1 + strlen(clientA_password);
    }
    else if (strcmp(username, "userB") == 0) {
        // copy the username and password into  buffer with a delimiter
        memcpy(&cred_buffer.data[0], &clientB_username[0], strlen(clientB_username));
        memcpy(&cred_buffer.data[strlen(clientB_username)], &STRING_DELIM, 1);
        memcpy(&cred_buffer.data[strlen(clientB_username) + 1], &clientB_password[0], strlen(clientB_password));
        cred_buffer.size = strlen(clientB_username) + 1 + strlen(clientB_password);
    }
    else {
        printf("Invalid username specified for authentication.\n");
        client_exit(1);
    }

    //printf("TLS: sending client authentication to server (%d bytes total)\n", cred_buffer.size);
    //hexPrint(cred_buffer.data, cred_buffer.size);

    result = write_message_to_tls(&cred_buffer, LOGIN);
    if (result ==1) {
        client_exit(1);
    }
}

void user_logout(char *username) {

    int result;
    BufferObject logout_buffer;

    // copy the username
    memcpy(&logout_buffer.data[0], &username[0], strlen(username));
    logout_buffer.size = strlen(username);

    //printf("TLS: sending client logout to server (%d bytes total)\n", logout_buffer.size);
    //hexPrint(logout_buffer.data, logout_buffer.size);

    result = write_message_to_tls(&logout_buffer, LOGOUT);
    if (result ==1) {
        client_exit(1);
    }
}

void file_permission_set(char *username) {

    int result;
    BufferObject this_buffer;

    // copy the username
    memcpy(&this_buffer.data[0], &username[0], strlen(username));
    this_buffer.size = strlen(username);

    result = write_message_to_tls(&this_buffer, SET_PERM);
    if (result ==1) {
        client_exit(1);
    }
}

void file_access(char *username) {

    int result;
    BufferObject this_buffer;

    // copy the username
    memcpy(&this_buffer.data[0], &username[0], strlen(username));
    this_buffer.size = strlen(username);

    result = write_message_to_tls(&this_buffer, GET_FILE);
    if (result ==1) {
        client_exit(1);
    }
}

void file_delegate(char *username1, char *username2) {

    int result;
    BufferObject this_buffer;

    // copy the usernames into buffer with a delimiter
    memcpy(&this_buffer.data[0], &username1[0], strlen(username1));
    memcpy(&this_buffer.data[strlen(username1)], &STRING_DELIM, 1);
    memcpy(&this_buffer.data[strlen(username1) + 1], &username2[0], strlen(username2));
    this_buffer.size = strlen(username1) + 1 + strlen(username2);

    result = write_message_to_tls(&this_buffer, DELEGATE_PERM);
    if (result ==1) {
        client_exit(1);
    }
}


void process_traffic(int duration) {

    // if the duration was specifed as 0 then listen forever
    // setting duration to INT_MAX will prevent packet counter from incrementing
    if (duration == 0) {
        duration = INT_MAX;
    }

    int maxfd, result;
    /* use select() to handle descriptors */
    maxfd = (maxfd > tcp_net_fd) ? maxfd : tcp_net_fd;

    // activity indicator flag
    int activity;
    // create a fd_set of sockets
    fd_set rd_set;
    // create buffer object for inbound and outbound packets
    BufferObject buffer_in, buffer_out;
    int packet_count = 0;
    while ((exit_requested == FALSE) && (packet_count < duration)) {
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

        // check if the activity was tcp on the network device
        if (FD_ISSET(tcp_net_fd, &rd_set)) {

            //tcp data: read it
            result = read_from_tls(&buffer_in);
            if (duration != INT_MAX) {packet_count++;}
            if (result ==1) {
                client_exit(1);
            }
            //printf("TLS channel read %d bytes\n", buffer_in.size);

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

    // initialize TLS
    result = initialize_tls(ca_cert,cert, priv_key, FALSE);
    if (result == 1) {
        client_exit(1);
    }

    // create socket for tcp channel
    result = create_tcp_socket();
    if (result ==1) {
        client_exit(1);
    }

    // create tcp connection to server
    result = connect_tcp_to_remote_server();
    if (result ==1) {
        client_exit(1);
    }

    // create TLS channel
    result = connect_to_tls();
    if (result ==1) {
        client_exit(1);
    }

    // authenticate to server over TLS
    printf("user_login(\"userA\", \"pwd123\");\n");
    send_client_credentials("userA");
    process_traffic(1);

    printf("user_login(\"userB\", \"pwd456\");\n");
    send_client_credentials("userB");
    process_traffic(1);

    printf("file_permission_set(\"userA\");\n");
    file_permission_set("userA");
    process_traffic(1);

    printf("file_access(\"userA\"); //success\n");
    file_access("userA");
    process_traffic(1);

    printf("file_access(\"userB\"); //failure\n");
    file_access("userB");
    process_traffic(1);

    printf("file_delegate(\"userA\", \"userB\");\n");
    file_delegate("userA", "userB");
    process_traffic(1);

    printf("file_access(\"userB\"); //success\n");
    file_access("userB");
    process_traffic(1);

    printf("user_logout(\"userA\");\n");
    user_logout("userA");
    process_traffic(1);

    printf("user_logout(\"userB\");\n");
    user_logout("userB");
    process_traffic(1);

    // listen for data from server
    process_traffic(0);

    client_exit(0);
}
