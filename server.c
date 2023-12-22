#include <stdio.h>
#include <string.h>

#include "auth/authentification.h"
#include "cJSON.h"

#include <stdlib.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <time.h>

#include <openssl/aes.h>
#include <openssl/rand.h>

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>

#define PUBLIC_KEY_FILE "public_key.pem"
#define PRIVATE_KEY_FILE "private_key.pem"
#define MAX_MESSAGE_LEN 100

#define MAX_USERNAME_LEN 500
#define MAX_PASSWORD_LEN 500
#define MAX_HASH_LEN (SHA256_DIGEST_LENGTH * 2) + 1
#define MAX_LINE_LEN 500

#define FILES_FOLDER "ServerFiles/"

#define MAX_KEY_LENGTH 32  // Assuming a maximum key length of 32 characters



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

char *decrypt_message(const unsigned char *ciphertext, const char *private_key_file) {
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


void writeToFile(const char *filename, const char *text) {
    // Define the folder name
    const char *folderName = FILES_FOLDER;

    // Create a buffer for the full file path
    char filePath[100];

    // Construct the full file path
    snprintf(filePath, sizeof(filePath), "%s%s", folderName, filename);

    // Open the file in append mode
    FILE *file = fopen(filePath, "a");

    // Check if the file was opened successfully
    if (file == NULL) {
        fprintf(stderr, "Error opening file %s\n", filePath);
        exit(EXIT_FAILURE);
    }

    // Write the text to the file
    fprintf(file, "%s", text);

    // Close the file
    fclose(file);
}

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

char* getFilesInFolder() {
    const char *folderPath = FILES_FOLDER;
    DIR *dir;
    struct dirent *entry;

    // Open the directory
    dir = opendir(folderPath);

    // Check if the directory was opened successfully
    if (dir == NULL) {
        perror("Error opening directory");
        exit(EXIT_FAILURE);
    }

    // Initialize a dynamic buffer to store file names
    char *filesBuffer = NULL;
    size_t bufferSize = 0;
    int fileNumber = 1;

    // Read file names and concatenate them with file numbers
    while ((entry = readdir(dir)) != NULL) {
        // Check if it is a regular file
        struct stat st;
        char filePath[1024];
        snprintf(filePath, 1024, "%s/%s", folderPath, entry->d_name);

        if (stat(filePath, &st) == 0 && S_ISREG(st.st_mode)) {
            // Calculate the size needed for the new file name
            size_t entrySize = snprintf(NULL, 0, "file number %d %s", fileNumber, entry->d_name) + 1;

            // Reallocate memory for the buffer
            filesBuffer = realloc(filesBuffer, bufferSize + entrySize);

            if (filesBuffer == NULL) {
                perror("Memory allocation error");
                closedir(dir);
                exit(EXIT_FAILURE);
            }

            // Copy the file name to the buffer with file number
            snprintf(filesBuffer + bufferSize, entrySize, "file number %d %s", fileNumber, entry->d_name);

            // Update the buffer size
            bufferSize += entrySize;
            fileNumber++;
        }
    }

    // Close the directory
    closedir(dir);

    return filesBuffer;
}



int main() {
    //generate public/private keys
    //generate_and_save_keys();
    // Start the server
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
    while(1==1){
        // Read the message on the server side         
        printf("Reading message on the server...\n");
        if (getmsg(received_message) == -1) {
            // Handle error
            fprintf(stderr, "Error: Failed to read message on the server.\n");
            return -1;
        }

        cJSON *json = cJSON_Parse(received_message); 

        if (json) {
            const char *username = cJSON_GetObjectItem(json, "username")->valuestring;
            const char *password = cJSON_GetObjectItem(json, "password")->valuestring;
            const char *command = cJSON_GetObjectItem(json, "command")->valuestring;
            const char *encrypted_key = cJSON_GetObjectItem(json, "encrypted_key")->valuestring;

            size_t outputLength;
            unsigned char* decodedCipher = base64_decode(encrypted_key,&outputLength);
            char *decrypted_key = decrypt_message(decodedCipher, PRIVATE_KEY_FILE);
            // printf("Decrypted key: %s\n", decrypted_key);

            size_t outputLengthPassword;
            unsigned char* decodedPassword = base64_decode(password,&outputLength);
            char *decPassword = decrypt_message(decodedPassword, PRIVATE_KEY_FILE);
            // printf("Decrypted pasword: %s\n", decPassword);

            //authentification
            
            if (!authenticate(username, decPassword)) {
                printf("Error: Authentication failed.\n");
                cJSON *jsonresp = cJSON_CreateObject();
                cJSON_AddStringToObject(jsonresp, "status", "failed");
                cJSON_AddStringToObject(jsonresp, "error","false credentials");

                // Convert the JSON object to a string
                char *message = cJSON_Print(jsonresp);
                printf("reponse --> %s \n",message);
                sndmsg(message,12346);
                continue;   
            } 

            char* token;
            if(strcmp(command,"save")==0){

                //generate token & send confirmation
                token=generateToken();
                cJSON *json = cJSON_CreateObject();
                cJSON_AddStringToObject(json, "status", "succeed");
                cJSON_AddStringToObject(json, "token",token);
                char *message = cJSON_Print(json);
                sndmsg(message,12346);


                char* fileStatus;
                do{
                    char* fileSection = (char *)malloc(2048 * sizeof(char));
                    getmsg(fileSection);
                    cJSON *json = cJSON_Parse(fileSection);
                    fileStatus = cJSON_GetObjectItem(json, "status")->valuestring;
                    const char *filename = cJSON_GetObjectItem(json, "filename")->valuestring;
                    if(strcmp(fileStatus,"not finished")==0){
                        const char *chunk = cJSON_GetObjectItem(json, "chunk")->valuestring;
                        unsigned char decrypted_chunk[1024];
                        size_t outputLength;
                        unsigned char* decodedCipher = base64_decode(chunk,&outputLength);
                        decryptAES(decodedCipher,(unsigned char*)decrypted_key,decrypted_chunk,outputLength);
                        // printf("decrypted chunk %s\n",decrypted_chunk);
                        writeToFile(filename,(char*)decrypted_chunk);
                    }
                    const char *newToken = cJSON_GetObjectItem(json, "token")->valuestring;
                    //test token

                }while(strcmp(fileStatus,"not finished")==0);

            }
            else if(strcmp(command,"list")==0){
                unsigned char* files = (unsigned char*)getFilesInFolder();
                cJSON *jsonresp = cJSON_CreateObject();
                cJSON_AddStringToObject(jsonresp, "status", "succeed");
                unsigned char encrypted_files_names[1024];
                size_t cipherLength;
                encryptAES(files,(unsigned char*)decrypted_key,encrypted_files_names,&cipherLength);            
                cJSON_AddStringToObject(jsonresp, "files",base64_encode(encrypted_files_names,cipherLength));
                char *message = cJSON_Print(jsonresp);
                sndmsg(message,12346);
            }
            else if(strcmp(command,"read")==0){
            }
            else{
                cJSON *json = cJSON_CreateObject();
                cJSON_AddStringToObject(json, "status", "failed");
                cJSON_AddStringToObject(json, "error","not permited command");

                // Convert the JSON object to a string
                char *message = cJSON_Print(json);
                sndmsg(message,12346);
            }
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