#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define PUBLIC_KEY_FILE "public_key.pem"
#define PRIVATE_KEY_FILE "private_key.pem"
#define MAX_MESSAGE_LEN 100

// Function to generate RSA key pair and save to files
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

// Function to encrypt a message using RSA public key
unsigned char *encrypt_message(const char *message, const char *public_key_file, int *ciphertext_len) {
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

    *ciphertext_len = RSA_size(public_key);
    unsigned char *ciphertext = malloc(*ciphertext_len);

    if (RSA_public_encrypt(strlen(message), (const unsigned char *)message, ciphertext, public_key, RSA_PKCS1_PADDING) == -1) {
        fprintf(stderr, "Error encrypting message.\n");
        exit(1);
    }

    RSA_free(public_key);
    printf("Message encrypted successfully.\n");
    return ciphertext;
}

// Function to decrypt a message using RSA private key
char *decrypt_message(const unsigned char *ciphertext, const char *private_key_file, int *decrypted_len) {
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
        exit(1);
    }

    *decrypted_len = strlen((char *)decrypted_message);
    RSA_free(private_key);
    printf("Message decrypted successfully.\n");
    return (char *)decrypted_message;
}

int main() {
    // Generate and save RSA key pair (comment this line after the first run)
    generate_and_save_keys();

    // Message to be encrypted and decrypted
    const char *original_message = "Hello, RSA encryption and decryption!";

    // Encrypt the message using the public key
    int ciphertext_len;
    unsigned char *ciphertext = encrypt_message(original_message, PUBLIC_KEY_FILE, &ciphertext_len);

    // Decrypt the message using the private key
    int decrypted_len;
    char *decrypted_message = decrypt_message(ciphertext, PRIVATE_KEY_FILE, &decrypted_len);

    // Print the results
    printf("Original Message: %s\n", original_message);
    printf("Encrypted Message: ");
    for (int i = 0; i < ciphertext_len; ++i) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    printf("Decrypted Message: %s\n", decrypted_message);

    // Free allocated memory
    free(ciphertext);
    free(decrypted_message);

    return 0;
}
