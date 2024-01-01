// encryption.h
#include <openssl/rand.h>
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

void encryptAES(const unsigned char *plaintext, const unsigned char *key, unsigned char *ciphertext, size_t *cipherLength);
void decryptAES(const unsigned char *ciphertext, const unsigned char *key, unsigned char *decryptedtext, size_t cipherLength);
char *base64_encode(const unsigned char *input, size_t length);
unsigned char *base64_decode(const char *input, size_t *output_length) ;
unsigned char *encrypt_message(const char *message, const char *public_key_file,int *outputLength);
unsigned char* sign_data(unsigned int* val) ;
#endif // ENCRYPTION_H
