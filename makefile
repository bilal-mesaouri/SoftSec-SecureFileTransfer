CC = gcc
CFLAGS = -Wall -std=c99
LIBS = -lcrypto -L. -lclient -lserver -lcjson -lssl -Wno-deprecated-declarations -Wno-implicit-function-declaration
OBJ = Src/encryption.o Src/file_operations.o Src/authentification.o

all: server

server: server.c $(OBJ) 
	$(CC) $(CFLAGS) -o $@ $< $(OBJ) $(LIBS)

Src/encryption.o: Src/encryption.c
	$(CC) $(CFLAGS) -c -o $@ $<

Src/file_operations.o: Src/fileOperations.c
	$(CC) $(CFLAGS) -c -o $@ $<

Src/authentification.o: Src/authentification.c
	$(CC) $(CFLAGS) -c -o $@ $<
clean:
	rm -f server $(OBJ)

.PHONY: all clean
