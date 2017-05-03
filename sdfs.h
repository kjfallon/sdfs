#ifndef SDFS_SDFS_H
#define SDFS_SDFS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <syslog.h>

/* OpenSSL provides cryptography libraries
 * https://www.openssl.org/ */
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

/* GLib provides additional data structures and logging framework
 * https://developer.gnome.org/glib/ */
#include <glib.h>

/* libconfuse provides support for using a configuration file
 * https://github.com/martinh/libconfuse */
#include <confuse.h>

/* Project specific header files */
#include "network/tcp.h"
#include "crypto/encrypt.h"
#include "crypto/mac.h"
#include "crypto/tls.h"
#include "output/console.h"

enum message_type {

    HELLO           = 0x01,
    OK              = 0x02,
    QUIT            = 0x03,
    LOGIN           = 0x04,
    LOGOUT          = 0x05,
    SET_PERM        = 0x06,
    DELEGATE_PERM   = 0x07,
    GET_FILE        = 0x08,
    FILE_DATA       = 0x09,
    BAD_COMMAND     = 0x0A,
    NOT_IMPLEMENTED = 0x0B

};

#endif //SDFS_SDFS_H
