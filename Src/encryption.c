#include "encryption.h"
#include <stdio.h>
#include <string.h>

#include "../clientFolder/Src/encryption.h"

#include <stdlib.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <time.h>

#include <openssl/aes.h>
#include <openssl/rand.h>


#define PUBLIC_KEY_FILE "Src/Client_public_key.pem"
#define PRIVATE_KEY_FILE "clientFolder/Src/Client_private_key.pem"

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

void generate_and_save_keys() {
    RSA *keypair = RSA_generate_key(2048, RSA_F4, NULL, NULL);

    // Save public key to file
    FILE *public_key_file = fopen(PUBLIC_KEY_FILE, "wb");
    PEM_write_RSAPublicKey(public_key_file, keypair);
    fclose(public_key_file);

    // Save private key to file
    FILE *private_key_file = fopen(PRIVATE_KEY_FILE, "wb");
    PEM_write_RSAPrivateKey(private_key_file, keypair, NULL, NULL, 0, NULL, NULL);
    fclose(private_key_file);

    RSA_free(keypair);

    printf("RSA key pair generated and saved to files.\n");
}

char *decrypt_message(const unsigned char *ciphertext,const char *private_key_file) {

    FILE *key_file = fopen(private_key_file, "rb");
    if (!key_file) {
        fprintf(stderr, "Error opening private key file.\n");
        exit(1);
    } 

    RSA *private_key = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);

    if (!private_key) {
        fprintf(stderr, "Error reading private key.\n");
        exit(1);
    }

    unsigned char *decrypted_message = malloc(RSA_size(private_key));

    if (RSA_private_decrypt(RSA_size(private_key), ciphertext, decrypted_message, private_key, RSA_PKCS1_PADDING) == -1) {
        fprintf(stderr, "Error decrypting message.\n");
        ERR_print_errors_fp(stderr);  // Print OpenSSL errors

        exit(1);
    }
    decrypted_message[RSA_size(private_key)] = '\0';
    RSA_free(private_key);
    printf("Message decrypted successfully.\n");
    return (char *)decrypted_message;
}
// Function to verify the signature using RSA public key
int verify_signature( const unsigned char *signature, size_t signature_len) {

    char* data = "hello Wrold";
    int data_len = strlen(data);
    FILE *public_key_file = fopen(PUBLIC_KEY_FILE, "r");
    if (!public_key_file) {
        perror("Error opening public key file");
        return -1;
    }

    RSA *rsa_public_key = PEM_read_RSAPublicKey(public_key_file, NULL, NULL, NULL);
    fclose(public_key_file);

    if (!rsa_public_key) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Compute the SHA-256 hash of the data
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)data, data_len, hash);

    // Verify the signature using the public key
    int result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, signature_len, rsa_public_key);

    RSA_free(rsa_public_key);
    return result;
}

// Function to generate a unique token
char* generateToken() {
    // Get current time
    time_t currentTime = time(NULL);

    // Seed the random number generator with the current time
    srand((unsigned int)currentTime);

    // Generate a random number
    int randomNum = rand();

    // Allocate memory for the token (adjust size as needed)
    char* token = (char*)malloc(20); // For example, a 20-character token

    // Generate a unique token based on current time and random number
    sprintf(token, "%ld_%d", currentTime, randomNum);

    return token;
}

void encryptAES(const unsigned char *plaintext, const unsigned char *key, unsigned char *ciphertext, size_t *cipherLength) {
    AES_KEY aesKey;
    AES_set_encrypt_key(key, 128, &aesKey);

    // Calculate the number of blocks
    size_t inputLength = strlen((char *)plaintext);
    size_t numBlocks = (inputLength + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

    printf("inside encryptAES: numBlocks=%ld\n", numBlocks);

    *cipherLength = numBlocks * AES_BLOCK_SIZE;

    printf("cipherLength=%ld\n", *cipherLength);

    // Encrypt each block
    for (size_t i = 0; i < numBlocks; ++i) {
        AES_encrypt(plaintext + i * AES_BLOCK_SIZE, ciphertext + i * AES_BLOCK_SIZE, &aesKey);
    }
    printf("hello\n");
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