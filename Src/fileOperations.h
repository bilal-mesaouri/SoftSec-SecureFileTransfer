#include <stdlib.h>

#ifndef FILE_OPERATIONS_H
#define FILE_OPERATIONS_H

char* readFileAndSend(const char* filename,unsigned char* Symetric_Encryption_Key,size_t chunkSize);
char* getFilesInFolder();
void writeToFile(const char *filename, const char *text);


#endif