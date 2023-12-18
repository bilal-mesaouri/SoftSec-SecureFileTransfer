CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -Wno-pointer-sign -Wdeprecated-declarations -Wimplicit-function-declaration
LDFLAGS = -L. -lserver -lssl -lcrypto libcjson.a

SRC_DIRS = auth encryption
OBJ_DIR = obj

# For the release build
CFLAGS_RELEASE = $(CFLAGS) -O2

# For the debugging build
CFLAGS_DEBUG = $(CFLAGS) -g -O0

SRCS = $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.c))
OBJS = $(patsubst %.c, $(OBJ_DIR)/%.o, $(SRCS))
OBJS_DEBUG = $(patsubst %.c, $(OBJ_DIR)/%_debug.o, $(SRCS))
MAIN_OBJ = server.o

TARGET = server
TARGET_DEBUG = server_debug

all: $(TARGET)

debug: $(TARGET_DEBUG)

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_RELEASE) -c $< -o $@

$(OBJ_DIR)/%_debug.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_DEBUG) -c $< -o $@

$(TARGET): $(OBJS) $(MAIN_OBJ)
	$(CC) $(CFLAGS_RELEASE) $^ -o $@ $(LDFLAGS)

$(TARGET_DEBUG): $(OBJS_DEBUG) $(OBJ_DIR)/$(MAIN_OBJ:%.o=%_debug.o)
	$(CC) $(CFLAGS_DEBUG) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf $(OBJ_DIR) $(TARGET) $(TARGET_DEBUG)

.PHONY: all debug clean
