#ifndef ENCRYPTION_H
#define ENCRYPTION_H

// Include necessary headers for your public key operations
#include <openssl/rsa.h>

// Function declarations
int generate_key_pair(const char *public_key_file, const char *private_key_file);
int decrypt_using_private_key(const char *encrypted_key, const char *private_key_file, char **decrypted_key);
#endif  // PUBLIC_KEY_H
