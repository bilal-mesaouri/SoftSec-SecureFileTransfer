#include "fileOperations.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "encryption.h"

#include "../cJSON.h"


#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>

#define FILES_FOLDER "ServerFiles/"

#define MAX_KEY_LENGTH 32  // Assuming a maximum key length of 32 characters

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
            printf("filename : %s\n", entry->d_name);

            // Calculate the size needed for the new file name
            size_t entrySize = snprintf(NULL, 0, "file number %d : %s", fileNumber, entry->d_name) + 1;

            // Reallocate memory for the buffer
            char *tempBuffer = realloc(filesBuffer, bufferSize + entrySize+2);

            if (tempBuffer == NULL) {
                perror("Memory allocation error"); 
                free(filesBuffer); // Free the original buffer in case realloc failed
                closedir(dir);
                exit(EXIT_FAILURE);
            }

            filesBuffer = tempBuffer; // Update pointer after successful realloc

            // Copy the file name to the buffer with file number
            if(fileNumber==1)strcpy(filesBuffer, "File number ");
            else strcat(filesBuffer, "\nFile number ");
            char str[20]; 
            // Convert integer to string
            sprintf(str, "%d", fileNumber);
            strcat(filesBuffer, str);
            strcat(filesBuffer, " : ");
            strcat(filesBuffer, entry->d_name);

            //fileNumber, entry->d_name
            printf("files buffer : %s\n",filesBuffer);
            // Update the buffer size
            bufferSize += entrySize;
            fileNumber++;
        }
    }

    // Close the directory
    closedir(dir);

    return filesBuffer;
}

char* readFileAndSend(const char* filename,unsigned char* Symetric_Encryption_Key,size_t chunkSize) {
    char FileFolder[512]=FILES_FOLDER; 
    printf("hola\n");
    printf("file name : %s\n",filename);
    strcat(FileFolder,filename);
    FILE* file = fopen(FileFolder, "rb"); // Open the file in binary mode

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
        printf("chunk -> %s\n",chunk);
        unsigned char encrypted_chunk [2048];
        size_t cipherLength;
        encryptAES(chunk,Symetric_Encryption_Key,encrypted_chunk,&cipherLength); 
        // Send the chunk using sndmsg
        printf("143");
        cJSON *json = cJSON_CreateObject();
        cJSON_AddStringToObject(json, "filename",filename);
        cJSON_AddStringToObject(json, "status","not finished");
        cJSON_AddStringToObject(json, "chunk",base64_encode(encrypted_chunk,cipherLength));
        sndmsg(cJSON_Print(json),12346);
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "filename",filename);
    cJSON_AddStringToObject(json, "status","finished");
    sndmsg(cJSON_Print(json),12346);
    // Close the file
    fclose(file);

    free(chunk);

    return "Read and sent successfully";
}