CC = gcc
CFLAGS = -Wall -std=c99
LIBS = -lcrypto -LLib -lclient -lserver -lcjson -lssl -Wno-deprecated-declarations -Wno-implicit-function-declaration
OBJ = Src/encryption.o Src/file_operations.o

all: client

client: client.c $(OBJ) 
	$(CC) $(CFLAGS) -o $@ $< $(OBJ) $(LIBS)

Src/encryption.o: Src/encryption.c
	$(CC) $(CFLAGS) -c -o $@ $<

Src/file_operations.o: Src/fileOperations.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f client $(OBJ)

.PHONY: all clean
