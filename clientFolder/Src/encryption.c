// encryption.c
#include "encryption.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <openssl/aes.h>
#include <openssl/rand.h>

#define PRIVATE_KEY_FILE "Src/Client_private_key.pem"

void encryptAES(const unsigned char *plaintext, const unsigned char *key, unsigned char *ciphertext, size_t *cipherLength) {
    AES_KEY aesKey;
    AES_set_encrypt_key(key, 128, &aesKey);

    // Calculate the number of blocks
    size_t inputLength = strlen((char *)plaintext);
    size_t numBlocks = (inputLength + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

    *cipherLength = numBlocks * AES_BLOCK_SIZE;

    // Encrypt each block
    for (size_t i = 0; i < numBlocks; ++i) {
        AES_encrypt(plaintext + i * AES_BLOCK_SIZE, ciphertext + i * AES_BLOCK_SIZE, &aesKey);
    }
}

void decryptAES(const unsigned char *ciphertext, const unsigned char *key, unsigned char *decryptedtext, size_t cipherLength) {
    AES_KEY aesKey;
    AES_set_decrypt_key(key, 128, &aesKey);

    // Calculate the number of blocks
    size_t numBlocks = cipherLength / AES_BLOCK_SIZE;

    // Decrypt each block
    for (size_t i = 0; i < numBlocks; ++i) {
        AES_decrypt(ciphertext + i * AES_BLOCK_SIZE, decryptedtext + i * AES_BLOCK_SIZE, &aesKey);
    }
}

// Function to Base64 encode data
char *base64_encode(const unsigned char *input, size_t length) {
    BIO *bio, *b64;
    FILE *stream;
    size_t encoded_size;
    char *encoded_data;

    // Create a BIO object to perform encoding
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    // Create a BIO object to write the encoded data
    bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);

    // Write the input data to the BIO
    BIO_write(b64, input, length);
    BIO_flush(b64);

    // Calculate the size of the encoded data
    encoded_size = BIO_get_mem_data(bio, &encoded_data);

    // Allocate memory for the encoded data
    char *result = (char *)malloc(encoded_size + 1);

    // Copy the encoded data to the result buffer
    memcpy(result, encoded_data, encoded_size);
    result[encoded_size] = '\0'; // Null-terminate the string

    // Clean up
    BIO_free_all(b64);

    return result;
}

unsigned char *base64_decode(const char *input, size_t *output_length) {
    BIO *bio, *b64;
    size_t length = strlen(input);
    unsigned char *buffer = (unsigned char *)malloc(length);

    // Create a BIO object to perform decoding
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    // Create a BIO object to read the encoded data
    bio = BIO_new_mem_buf((void *)input, length);
    bio = BIO_push(b64, bio);

    // Perform decoding
    *output_length = BIO_read(bio, buffer, length);

    // Clean up
    BIO_free_all(b64);

    return buffer;
}

// Function to encrypt a message using RSA public key
unsigned char *encrypt_message(const char *message, const char *public_key_file,int *outputLength) {
    FILE *key_file = fopen(public_key_file, "rb");
    if (!key_file) {
        fprintf(stderr, "Error opening public key file.\n");
        exit(1);
    }

    RSA *public_key = PEM_read_RSAPublicKey(key_file, NULL, NULL, NULL);
    fclose(key_file);

    if (!public_key) {
        fprintf(stderr, "Error reading public key.\n");
        exit(1);
    }
    *outputLength = RSA_size(public_key);
    unsigned char *ciphertext = malloc(RSA_size(public_key));

    if (RSA_public_encrypt(strlen(message), (const unsigned char *)message, ciphertext, public_key, RSA_PKCS1_PADDING) == -1) {
        fprintf(stderr, "Error encrypting message.\n");
        exit(1);
    }

    RSA_free(public_key);
    return ciphertext;
}

unsigned char* sign_data(unsigned int* sigSize) {
    char* data = "hello Wrold";
    size_t dataLen = strlen(data);
    FILE *key_file = fopen(PRIVATE_KEY_FILE, "rb");

    if (!key_file) {
        fprintf(stderr, "Error opening private key filelkjh.\n");
        exit(1);
    }

    RSA *private_key = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);

    if (!private_key) {
        fprintf(stderr, "Error reading private key.\n");
        exit(1);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char *signature = malloc(RSA_size(private_key));
    SHA256((const unsigned char *)data, dataLen, hash);
   


    if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, sigSize, private_key) != 1) {
        fprintf(stderr, "Error signing data.\n");
        exit(1);
    }
    
    return signature;
}
