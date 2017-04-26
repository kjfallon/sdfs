
#ifndef SDFS_ENCRYPT_H
#define SDFS_ENCRYPT_H

#include <stdint.h>
#include <stddef.h>


/* mesage buffer (1500-28) = 1472, 1472*10 = 14720 */
#define BUFSIZE 14720

#define IV_SIZE 16
#define KEY_SIZE 16

typedef struct {
    uint8_t data[BUFSIZE];
    size_t size;
} BufferObject;

int message_encrypt(BufferObject *in_buffer, BufferObject *out_buffer);
int message_decrypt(BufferObject *in_buffer, BufferObject *out_buffer );

#endif //SDFS_ENCRYPT_H
