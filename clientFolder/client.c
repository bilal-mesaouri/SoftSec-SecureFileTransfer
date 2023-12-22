#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include "cJSON.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <openssl/aes.h>
#include <openssl/rand.h>

#define PUBLIC_KEY_FILE "public_key.pem"

#define MAX_MESSAGE_LEN 100

#define MAX_USERNAME_LEN 50
#define MAX_PASSWORD_LEN 50

#define PORT 12345


#define MAX_KEY_LENGTH 32  // Assuming a maximum key length of 32 characters

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

int InitializeCommunication(char* username,char* password,char* Symetric_Encryption_Key,char* command,char** response){

    // Encrypt the message using the public key
    int outputLengthCipher ;
    unsigned char *ciphertext = encrypt_message(Symetric_Encryption_Key, PUBLIC_KEY_FILE,&outputLengthCipher);
    char* encodedcipher = base64_encode(ciphertext,outputLengthCipher);

    unsigned char *cipherPassword = encrypt_message(password, PUBLIC_KEY_FILE,&outputLengthCipher);
    char* encodedPassword = base64_encode(cipherPassword,outputLengthCipher);

    // Create a JSON object
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "username", username);
    cJSON_AddStringToObject(json, "password",encodedPassword);
    cJSON_AddStringToObject(json, "command",command);
    cJSON_AddStringToObject(json, "encrypted_key", encodedcipher);

    // Convert the JSON object to a string
    char *message = cJSON_Print(json);
    int result = sndmsg(message, PORT);
    if (result == -1) {
        fprintf(stderr, "Error: Failed to send message.\n");
        return -1;
    } else {
        printf("Message sent successfully.\n");

        *response = (char *)malloc(1024 * sizeof(char));
        if(getmsg(*response)==-1)printf("couldnt read the response");
        
    }

    // Free allocated memory
    cJSON_free(message);
    cJSON_Delete(json);

    // Free the allocated memory
    free(ciphertext);

    return 0;

}

char* readFileAndSend(const char* filename,unsigned char* Symetric_Encryption_Key,size_t chunkSize,const char* token) {
    FILE* file = fopen(filename, "rb"); // Open the file in binary mode

    if (file == NULL) {
        fprintf(stderr, "Unable to open file %s\n", filename);
        return NULL;
    }

    unsigned char* chunk = (unsigned char*)malloc(chunkSize + 1); // Allocate memory for chunks (add 1 for null terminator)

    if (chunk == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            fclose(file);
            return NULL;
        }

        size_t bytesRead;
    while ((bytesRead = fread(chunk, 1, chunkSize, file)) > 0) {
        // Null-terminate the chunk
        chunk[bytesRead] = '\0';
        
        unsigned char encrypted_chunk[2048];
        size_t cipherLength;
        encryptAES(chunk,Symetric_Encryption_Key,encrypted_chunk,&cipherLength); 
        // Send the chunk using sndmsg
        cJSON *json = cJSON_CreateObject();
        cJSON_AddStringToObject(json, "token",token);
        cJSON_AddStringToObject(json, "filename",filename);
        cJSON_AddStringToObject(json, "status","not finished");
        cJSON_AddStringToObject(json, "chunk",base64_encode(encrypted_chunk,cipherLength));
        sndmsg(cJSON_Print(json),12345);
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "token",token);
    cJSON_AddStringToObject(json, "filename",filename);
    cJSON_AddStringToObject(json, "status","finished");
    sndmsg(cJSON_Print(json),12345);
    // Close the file
    fclose(file);

    free(chunk);

    return "Read and sent successfully";
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




int main() {
    startserver(12346);

    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    char Symetric_Encryption_Key[1024];
    char command[10];

    {printf("Enter username: ");
    scanf("%s", username);

    printf("Enter password: ");
    scanf("%s", password);

    printf("Enter command: ");
    scanf("%s", command);}

    printf("Enter an encryption Key: ");
    scanf("%s", Symetric_Encryption_Key);

    
    char *response;
    if(InitializeCommunication(username,password,Symetric_Encryption_Key,command,&response)==0){
        cJSON *json = cJSON_Parse(response);
        const char *status = cJSON_GetObjectItem(json, "status")->valuestring;

        if(strcmp(status,"failed")==0){
            const char *error = cJSON_GetObjectItem(json, "error")->valuestring;
            printf("status : %s",error);
            return -1;
        }
        printf("successfully authentified !!\n");
        
        if(strcmp(command,"save")==0){
            char filename[128];
            printf("Enter a file path : ");
            scanf("%s", filename);
            size_t chunkSize = 512;
            const char *token = cJSON_GetObjectItem(json, "token")->valuestring;
            char* result = readFileAndSend(filename,(unsigned char*)Symetric_Encryption_Key, chunkSize,token);
        }
        else if(strcmp(command,"list")==0){
            char *files_enc = cJSON_GetObjectItem(json, "files")->valuestring;
            unsigned char files_names[1024];
            size_t PlainTextLength;
            unsigned char* filesNamesDecoded = base64_decode(files_enc,&PlainTextLength);
            decryptAES(filesNamesDecoded,(unsigned char*)Symetric_Encryption_Key,files_names,PlainTextLength);
            printf("Files :\n%s\n",files_names);
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

    
    
    stopserver();
    return 0;
}




