#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#define MAX_USERNAME_LEN 500
#define MAX_PASSWORD_LEN 500
#define MAX_HASH_LEN (SHA256_DIGEST_LENGTH * 2) + 1
#define MAX_LINE_LEN 500

int hash_password(const char *password, char *hashed_password);

int authenticate(const char *username, const char *password);

void register_user(const char *username, const char *password);

#endif // AUTHENTICATION_H
