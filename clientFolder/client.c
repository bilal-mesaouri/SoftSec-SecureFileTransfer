#include <stdio.h>
#include <stdlib.h>

#include "Src/encryption.h"
#include "Src/fileOperations.h"

#include <string.h>
#include "Lib/cJSON.h"


#define PUBLIC_KEY_FILE "public_key.pem"

#define MAX_MESSAGE_LEN 100

#define MAX_USERNAME_LEN 50
#define MAX_PASSWORD_LEN 50

#define PORT 12345


#define MAX_KEY_LENGTH 32  // Assuming a maximum key length of 32 characters

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

void get_user_input(char *username, char *password, char *command, char *symmetric_encryption_key){

    printf("Enter username: ");
    scanf("%s", username);

    printf("Enter password: ");
    scanf("%s", password);

    printf("Enter command: ");
    scanf("%s", command);

    printf("Enter an encryption Key: ");
    scanf("%s", symmetric_encryption_key);
}


int main() {
    startserver(12346);

    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    char Symetric_Encryption_Key[1024];
    char command[10];

    get_user_input(username, password, command, Symetric_Encryption_Key);


    
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
            char* result = readClientFileAndSend(filename,(unsigned char*)Symetric_Encryption_Key, chunkSize);
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
            char filename[128];
            printf("Enter a file to be downloaded : ");
            scanf("%s", filename);
            sndmsg(filename,12345);
            getFileFromServer(Symetric_Encryption_Key);


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




