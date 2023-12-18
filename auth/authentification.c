#include"authentification.h"
#define MAX_USERNAME_LEN 500
#define MAX_PASSWORD_LEN 500
#define MAX_HASH_LEN (SHA256_DIGEST_LENGTH * 2) + 1
#define MAX_LINE_LEN 500

int hash_password(const char *password, char *hashed_password) {
    // Use SHA256 for simplicity; you may choose a different hash algorithm
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    // Ensure hashed_password buffer is large enough
    if (strlen(hashed_password) >= MAX_HASH_LEN) {
        fprintf(stderr, "Error: Insufficient buffer size in hash_password.\n");
        return 0;
    }

    // Convert the binary hash to a hexadecimal string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(&hashed_password[i * 2], 3, "%02x", (unsigned int) hash[i]);
    }

    return 1;
}


int authenticate(const char *username, const char *password) {
    FILE *authFile = fopen("auth.txt", "r");
    if (authFile == NULL) {
        fprintf(stderr, "Error: Failed to open the authentication file.\n");
        return 0; // Authentication failed
    }

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), authFile) != NULL) {
        char stored_username[MAX_USERNAME_LEN];
        char stored_hash[MAX_PASSWORD_LEN];

        if (sscanf(line, "%[^#]#%[^\n]", stored_username, stored_hash) == 2) {


            if (strcmp(username, stored_username) == 0) {
                // Username match, hash the entered password and compare
                unsigned char entered_hash[MAX_PASSWORD_LEN];
                hash_password(password, entered_hash);
                if (strcmp((char *) entered_hash, stored_hash) == 0) {
                    fclose(authFile);
                    return 1; // Authentication successful
                }
            }
        }
    }

    fclose(authFile);
    return 0; // Authentication failed
}


void register_user(const char *username, const char *password) {
    FILE *authFile = fopen("auth.txt", "a");
    if (authFile == NULL) {
        fprintf(stderr, "Error: Failed to open the authentication file for registration.\n");
        return;
    }

    // Hash the password
    char hashed_password[MAX_HASH_LEN];
    if (!hash_password(password, hashed_password)) {
        fclose(authFile);
        return;
    }

    // Append the new username and hashed password to the file
    fprintf(authFile, "%s#%s\n", username, hashed_password);

    fclose(authFile);
}