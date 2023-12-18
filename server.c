#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include "auth/authentification.h"
#include "encryption/encryption.h"
#include "cJSON.h"

#define MAX_USERNAME_LEN 500
#define MAX_PASSWORD_LEN 500
#define MAX_HASH_LEN (SHA256_DIGEST_LENGTH * 2) + 1
#define MAX_LINE_LEN 500


int main() {
    //generate public/private keys
    // if (generate_key_pair("public_key.pem", "private_key.pem") == 0) {
    //     printf("Key pair generated successfully.\n");
    // } else {
    //     fprintf(stderr, "Error generating key pair.\n");
    // }
    
    // Start the server
    printf("Starting the server...\n");
    if (startserver(12345) == -1) {
        // Handle error
        fprintf(stderr, "Error: Failed to start the server.\n");
        return 1;
    }
    printf("Server started successfully.\n");


    // // Check if the user is registering or authenticating
     int choice;
    do{
        printf("Enter 1 to register, anything else to start the server : ");

        scanf("%d", &choice);
    
        if (choice == 1) {
            char username[MAX_USERNAME_LEN];
            char password[MAX_PASSWORD_LEN];
            printf("Enter username: ");
            scanf("%s", username);

            printf("Enter password: ");
            scanf("%s", password);
            // Register the new user
            register_user(username, password);
            printf("User registered successfully.\n");
        }

    }while(choice==1);


    char* received_message = (char *)malloc(1024 * sizeof(char));
    while(1==1) {
        // Read the message on the server side         
        printf("Reading message on the server...\n");
        if (getmsg(received_message) == -1) {
            // Handle error
            fprintf(stderr, "Error: Failed to read message on the server.\n");
            return 1;
        }

        cJSON *json = cJSON_Parse(received_message);

        if (json) {
            const char *username = cJSON_GetObjectItem(json, "username")->valuestring;
            const char *password = cJSON_GetObjectItem(json, "password")->valuestring;
            const char *encrypted_key = cJSON_GetObjectItem(json, "encrypted_key")->valuestring;

            const char *decrypted_key;
            if (decrypt_using_private_key(encrypted_key,"private_key.pem",&decrypted_key)==0) {
                printf("Symmetric key decrypted successfully.\n");
                printf("Decrypted Key: %s\n", decrypted_key);
            } else {
                fprintf(stderr, "Error decrypting symmetric key.\n");
            }
            if (!authenticate(username, password)) {
                fprintf(stderr, "Error: Authentication failed.\n");
                continue ;
            } else {
                printf("Authentication successful.\n");
            }

            // Free the allocated memory
            free(encrypted_key);
            free(decrypted_key);

        }
        
    }

    // Stop the server
    printf("Stopping the server...\n");
    if (stopserver() == -1) {
        // Handle error
        fprintf(stderr, "Error: Failed to stop the server.\n");
        return 1;
    }
    printf("Server stopped successfully.\n");

    return 0;
}