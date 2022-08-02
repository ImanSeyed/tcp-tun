CC := gcc
CFLAGS := -Wall -Wextra
SOURCES := $(wildcard src/*.c src/*/*.c)

all:
	$(CC) $(SOURCES) $(CFLAGS) -o tcp-tun
clean:
	rm -rf tcp-tun
