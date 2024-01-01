// encryption.h
#include <openssl/rand.h>
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

void encryptAES(const unsigned char *plaintext, const unsigned char *key, unsigned char *ciphertext, size_t *cipherLength);
void decryptAES(const unsigned char *ciphertext, const unsigned char *key, unsigned char *decryptedtext, size_t cipherLength) ;
char *base64_encode(const unsigned char *input, size_t length);
unsigned char *base64_decode(const char *input, size_t *output_length) ;
unsigned char *encrypt_message(const char *message, const char *public_key_file,int *outputLength);
void generate_and_save_keys();
char* generateToken();
char *decrypt_message(const unsigned char *ciphertext,const char *private_key_file) ;
int verify_signature(const unsigned char *signature, size_t signature_len);
unsigned char* sign_data();
#endif // ENCRYPTION_H
