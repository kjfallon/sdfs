

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

#include "mac.h"

extern unsigned char session_hmac_key[KEY_SIZE];

void message_authentication(BufferObject *buffer, uint8_t *digest ) {
    uint32_t digest_length = SHA256_DIGEST_LENGTH;
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, session_hmac_key, KEY_SIZE, EVP_sha256(), NULL);
    HMAC_Update(&ctx, buffer->data, buffer->size);
    HMAC_Final(&ctx, digest, &digest_length);
    HMAC_CTX_cleanup(&ctx);
}

