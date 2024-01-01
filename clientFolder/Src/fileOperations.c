#include <stdio.h>
#include <stdlib.h>

#include "encryption.h"

#include <string.h>
#include "../Lib/cJSON.h"


char* readClientFileAndSend(const char* filename,unsigned char* Symetric_Encryption_Key,size_t chunkSize) {


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
        char* data = "hello Wrold";
        size_t dataLen = strlen(data);
        unsigned int chunkSignatureLength ;
        unsigned char* ChunkSignature = sign_data(&chunkSignatureLength);
        unsigned char encrypted_chunk[2048];
        size_t cipherLength;
        encryptAES(chunk,Symetric_Encryption_Key,encrypted_chunk,&cipherLength); 
        //Send the chunk using sndmsg
        cJSON *json = cJSON_CreateObject();
        cJSON_AddStringToObject(json, "filename",filename);
        char* encodedSgnature = base64_encode(ChunkSignature,chunkSignatureLength);
        cJSON_AddStringToObject(json, "signature",encodedSgnature);
        cJSON_AddStringToObject(json, "status","not finished");
        cJSON_AddStringToObject(json, "chunk",base64_encode(encrypted_chunk,cipherLength));
        sndmsg(cJSON_Print(json),12345);
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "filename",filename);
    cJSON_AddStringToObject(json, "status","finished");
    sndmsg(cJSON_Print(json),12345);
    // Close the file
    fclose(file);

    free(chunk);

    return "Read and sent successfully";
}

void writeToFile(const char *filename, const char *text) {
    // Define the folder name
    const char *folderName = "Download/";

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

void getFileFromServer(char* decrypted_key){

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
    }while(strcmp(fileStatus,"not finished")==0);
}
