CC := gcc
CFLAGS := -Wall -Wextra
SOURCES := $(wildcard tcp-tun/src/*.c tcp-tun/src/*/*.c)

all:
	$(CC) $(SOURCES) $(CFLAGS) -o tcp-tun.out
clean:
	rm -rf tcp-tun.out
