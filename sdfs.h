#ifndef SDFS_SDFS_H
#define SDFS_SDFS_H

enum message_type {

    HELLO           = 0x01,
    OK              = 0x02,
    BAD_NONCE       = 0x03,
    LOGIN           = 0x04,
    LOGOUT          = 0x05,
    SET_PERM        = 0x06,
    DELEGATE_PERM   = 0x07,
    GET_FILE        = 0x08,
    FILE_DATA       = 0x09,
    BAD_COMMAND     = 0x0A,
    SET_KEY         = 0x0B

};

#endif //SDFS_SDFS_H
