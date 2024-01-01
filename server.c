#include <stdio.h>
#include <string.h>

#include "Src/authentification.h"
#include "Src/fileOperations.h"
#include "Src/encryption.h"
#include "cJSON.h"

#include <stdlib.h>

#define PUBLIC_KEY_FILE "public_key.pem"
#define PRIVATE_KEY_FILE "Src/private_key.pem"

#define MAX_MESSAGE_LEN 100

#define MAX_USERNAME_LEN 500
#define MAX_PASSWORD_LEN 500
#define MAX_HASH_LEN (SHA256_DIGEST_LENGTH * 2) + 1
#define MAX_LINE_LEN 500

#define FILES_FOLDER "ServerFiles/"

#define MAX_KEY_LENGTH 32  // Assuming a maximum key length of 32 characters


void addNewClient(){
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
}

void process_json(cJSON* json,const char **username, const char **password, const char **command, const char **encrypted_key,char** dec_password,char** decrypted_key) {
    *username = cJSON_GetObjectItem(json, "username")->valuestring;
    *password = cJSON_GetObjectItem(json, "password")->valuestring;
    *command = cJSON_GetObjectItem(json, "command")->valuestring;
    *encrypted_key = cJSON_GetObjectItem(json, "encrypted_key")->valuestring;
    size_t output_length;
    unsigned char *decoded_cipher = base64_decode(*encrypted_key, &output_length);

    *decrypted_key = decrypt_message(decoded_cipher,PRIVATE_KEY_FILE);

    size_t output_length_password;
    unsigned char *decoded_password = base64_decode(*password, &output_length_password);
    *dec_password = decrypt_message(decoded_password,PRIVATE_KEY_FILE);


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
    addNewClient();


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
            const char* username ;
            const char* password ;
            const char* command ;
            const char* encrypted_key;
            char* decrypted_key ;
            char* decPassword ;

            process_json(json,&username,&password,&command,&encrypted_key,&decPassword,&decrypted_key);

            //authentification
            
            if (!authenticate(username, decPassword)) {
                printf("Error: Authentication failed.\n");
                cJSON *jsonresp = cJSON_CreateObject();
                cJSON_AddStringToObject(jsonresp, "status", "failed");
                cJSON_AddStringToObject(jsonresp, "error","false credentials");

                // Convert the JSON object to a string
                char *message = cJSON_Print(jsonresp);
                sndmsg(message,12346);
                continue;   
            } 

            if(strcmp(command,"save")==0){

                //generate token & send confirmation
                cJSON *json = cJSON_CreateObject();
                cJSON_AddStringToObject(json, "status", "succeed");
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
                        char* encodedSignature = cJSON_GetObjectItem(json, "signature")->valuestring;
                        const char *chunk = cJSON_GetObjectItem(json, "chunk")->valuestring;
                        unsigned char decrypted_chunk[1024];
                        size_t outputLength;
                        unsigned char* decodedCipher = base64_decode(chunk,&outputLength);
                        decryptAES(decodedCipher,(unsigned char*)decrypted_key,decrypted_chunk,outputLength);
                        size_t signatureLength ;
                        unsigned char* ddecodedsignature = base64_decode(encodedSignature,&signatureLength);
                        if(verify_signature(ddecodedsignature,signatureLength)==1){
                            printf("signature verified successfully ...\n");
                            printf("decrypted chunk %s\n",decrypted_chunk);
                            writeToFile(filename,(char*)decrypted_chunk);
                        }
                    }

                    

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
                cJSON *json = cJSON_CreateObject();
                cJSON_AddStringToObject(json, "status", "succeed");
                char *message = cJSON_Print(json);
                sndmsg(message,12346);

                char* filename = (char*)malloc(1024*sizeof(char));
                getmsg(filename);
                printf("filename -> %s\n",filename);
                char* results = readFileAndSend(filename,(unsigned char*)decrypted_key,512);
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
    if (stopserver() == -1) {
        // Handle error
        fprintf(stderr, "Error: Failed to stop the server.\n");
        return 1;
    }
    printf("Server stopped successfully.\n");

    return 0;

}