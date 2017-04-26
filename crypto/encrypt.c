#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "encrypt.h"
#include "mac.h"

extern unsigned char session_encryption_key[KEY_SIZE];
extern unsigned char cbc_iv[IV_SIZE];

int message_encrypt(BufferObject *in_buffer, BufferObject *out_buffer) {

    // iv||Enc(client_packet)||hmac(iv||Enc(client_packet))
    // --  ------------------  ----------------------------
    // 16      buf-(16+32)                  32

    // AES-CBC must use new random iv each use of encryption function
    // reuse of iv aka. "session iv" is not CPA secure and results in flawed
    // implementation of AES-CBC
    RAND_bytes(cbc_iv, IV_SIZE);

    BufferObject encrypted_packet_temp_buffer;

    // encrypt client packet to the temp_buffer
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, session_encryption_key, cbc_iv);
    int outlen, tmplen;

    if(!EVP_EncryptUpdate(&ctx, encrypted_packet_temp_buffer.data, &outlen, in_buffer->data, in_buffer->size))
    {
        // encryption error
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 1;
    }
    /* Buffer passed to EVP_EncryptFinal() must be after data just
     * encrypted to avoid overwriting it.
     */
    if(!EVP_EncryptFinal_ex(&ctx, encrypted_packet_temp_buffer.data + outlen, &tmplen))
    {
        // encryption error
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 1;
    }
    outlen += tmplen;
    encrypted_packet_temp_buffer.size = outlen;

    // concatenate iv and encrypted data
    memcpy(&out_buffer->data[0],&cbc_iv[0], IV_SIZE);
    memcpy(&out_buffer->data[IV_SIZE],&encrypted_packet_temp_buffer.data[0], encrypted_packet_temp_buffer.size);
    out_buffer->size = IV_SIZE + encrypted_packet_temp_buffer.size;

    // apply HMAC to iv and encrypted data
    message_authentication(out_buffer, &out_buffer->data[out_buffer->size] );
    out_buffer->size += SHA256_DIGEST_LENGTH;

    if( out_buffer->size > BUFSIZE ) {
        printf("ERROR in encrypt(), encrypted buffer is too large %d.\n",out_buffer->size );
        return 1;
    }

    return 0;
}

int message_decrypt(BufferObject *in_buffer, BufferObject *out_buffer )
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    in_buffer->size -= SHA256_DIGEST_LENGTH;

    // calculate HMAC digest to verify it is the same as we were given
    message_authentication(in_buffer, digest);
    //compare results
    if( memcmp(&in_buffer->data[in_buffer->size], digest, SHA256_DIGEST_LENGTH) ) {
        printf("ERROR HMAC validation\n" );
        return 1;
    }

    // the input buffer now contains the IV and encrypted data, lets separate them.
    BufferObject temp_buffer;
    memcpy(&cbc_iv[0],&in_buffer->data[0], IV_SIZE);
    //printf("decryption iv: ");
    //hexPrint(cbc_iv,IV_SIZE);

    in_buffer->size -= IV_SIZE;
    memcpy(&temp_buffer.data[0], &in_buffer->data[IV_SIZE], in_buffer->size);
    temp_buffer.size = in_buffer->size;

    // perform decryption with session key, and iv for this packet
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, session_encryption_key, cbc_iv);
    int outlen, tmplen;

    if(!EVP_DecryptUpdate(&ctx, out_buffer->data, &outlen, temp_buffer.data, temp_buffer.size))
    {
        // decryption error
        EVP_CIPHER_CTX_cleanup(&ctx);
        printf ("Decryption Error in DecryptUpdate!\n\n");
        return 1;
    }
    /* Buffer passed to EVP_EncryptFinal() must be after data just
     * encrypted to avoid overwriting it.
     */

    if(!EVP_DecryptFinal_ex(&ctx, out_buffer->data + outlen, &tmplen))
    {
        // decryption error
        EVP_CIPHER_CTX_cleanup(&ctx);
        printf ("Decryption Error in DecryptFinal!\n\n");
        return 1;
    }
    outlen += tmplen;
    out_buffer->size = outlen;

    return 0;

}