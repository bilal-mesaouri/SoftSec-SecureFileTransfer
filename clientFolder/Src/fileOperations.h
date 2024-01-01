// file_operations.h
#include <stdlib.h>
#ifndef FILE_OPERATIONS_H
#define FILE_OPERATIONS_H


char* readClientFileAndSend(const char* filename,unsigned char* Symetric_Encryption_Key,size_t chunkSize) ;
void writeToFile(const char *filename, const char *text);
void getFileFromServer(char* decrypted_key);

#endif // FILE_OPERATIONS_H
