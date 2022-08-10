CC := gcc
CFLAGS := -Wall -Wextra
SOURCES := $(wildcard src/*.c src/*/*.c)
INCLUDE_DIR := include/

all:
	$(CC) $(SOURCES) $(CFLAGS) -I $(INCLUDE_DIR) -o tcp-tun
clean:
	rm -rf tcp-tun
