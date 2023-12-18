#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>
#include "cJSON.h"

#define MAX_USERNAME_LEN 50
#define MAX_PASSWORD_LEN 50





// Function to encrypt symmetric key
int encrypt_using_public_key(const char *symmetric_key, const char *public_key_file, char **encrypted_key) {
    RSA *public_key = NULL;
    FILE *key_file = fopen(public_key_file, "r");

    if (!key_file) {
        fprintf(stderr, "Error opening public key file.\n");
        return 1;
    }

    public_key = PEM_read_RSAPublicKey(key_file, NULL, NULL, NULL);
    fclose(key_file);

    if (!public_key) {
        fprintf(stderr, "Error reading public key.\n");
        return 1;
    }

    *encrypted_key = malloc(RSA_size(public_key));

    int result = RSA_public_encrypt(strlen(symmetric_key), (const unsigned char *)symmetric_key,
                                    (unsigned char *)*encrypted_key, public_key, RSA_PKCS1_OAEP_PADDING);

    RSA_free(public_key);

    if (result == -1) {
        fprintf(stderr, "Error encrypting symmetric key.\n");
        return 1;
    }

    return 0;
}

int main() {
    int port = 12345;
    const char *symmetric_key = "helloWorld!";
    char *encrypted_key;
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    printf("Enter username: ");
    scanf("%s", username);

    printf("Enter password: ");
    scanf("%s", password);

    // Encrypt the symmetric key
    if (encrypt_using_public_key(symmetric_key, "public_key.pem", &encrypted_key) == 0) {
        printf("Symmetric key encrypted successfully.\n");

        // Create a JSON object
        cJSON *json = cJSON_CreateObject();
        cJSON_AddStringToObject(json, "username", username);
        cJSON_AddStringToObject(json, "password",password);
        cJSON_AddStringToObject(json, "encrypted_key", encrypted_key);

        // Convert the JSON object to a string
        char *message = cJSON_Print(json);
        
        int result = sndmsg(message, port);
        if (result == -1) {
            fprintf(stderr, "Error: Failed to send message.\n");
        } else {
            printf("Message sent successfully.\n");
        }
        // Free allocated memory
        cJSON_free(message);
        cJSON_Delete(json);

        // Free the allocated memory
        free(encrypted_key);
    } else {
        fprintf(stderr, "Error encrypting symmetric key.\n");
    }

    return 0;
}
