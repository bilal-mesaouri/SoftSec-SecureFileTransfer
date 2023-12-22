CC = gcc
CFLAGS = -Wall -std=c99
LIBS = -lcrypto -L. -lclient -lserver libcjson.a -lssl -Wno-deprecated-declarations -Wno-implicit-function-declaration   

all: client

client: client.c libcjson.a
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f client

.PHONY: all clean
