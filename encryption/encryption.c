#include"encryption.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>

// Function to generate RSA key pair
int generate_key_pair(const char *public_key_file, const char *private_key_file) {
    int key_size = 2048;
    RSA *keypair = RSA_new();
    BIGNUM *e = BN_new();

    if (!keypair || !e) {
        fprintf(stderr, "Error allocating memory for RSA key pair.\n");
        return 1;
    }

    if (BN_set_word(e, RSA_F4) != 1) {
        fprintf(stderr, "Error setting public exponent.\n");
        RSA_free(keypair);
        BN_free(e);
        return 1;
    }

    if (RSA_generate_key_ex(keypair, key_size, e, NULL) != 1) {
        fprintf(stderr, "Error generating RSA key pair.\n");
        RSA_free(keypair);
        BN_free(e);
        return 1;
    }

    FILE *public_file = fopen(public_key_file, "w");
    FILE *private_file = fopen(private_key_file, "w");

    if (!public_file || !private_file ||
        !PEM_write_RSAPublicKey(public_file, keypair) ||
        !PEM_write_RSAPrivateKey(private_file, keypair, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Error writing key files.\n");
        fclose(public_file);
        fclose(private_file);
        RSA_free(keypair);
        BN_free(e);
        return 1;
    }

    fclose(public_file);
    fclose(private_file);
    RSA_free(keypair);
    BN_free(e);

    return 0;
}


// Function to decrypt symmetric key
int decrypt_using_private_key(const char *encrypted_key, const char *private_key_file, char **decrypted_key) {
    RSA *private_key = NULL;
    FILE *key_file = fopen(private_key_file, "r");

    if (!key_file) {
        fprintf(stderr, "Error opening private key file.\n");
        return 1;
    }

    private_key = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);

    if (!private_key) {
        fprintf(stderr, "Error reading private key.\n");
        return 1;
    }

    *decrypted_key = malloc(RSA_size(private_key));

    int result = RSA_private_decrypt(RSA_size(private_key), (const unsigned char *)encrypted_key,
                                     (unsigned char *)*decrypted_key, private_key, RSA_PKCS1_OAEP_PADDING);

    RSA_free(private_key);

    if (result == -1) {
        fprintf(stderr, "Error decrypting symmetric key.\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    return 0;
}


