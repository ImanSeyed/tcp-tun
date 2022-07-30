CC := gcc
CFLAGS := -Wall -Wextra
override CFLAGS :=
SOURCES := $(wildcard src/*.c)

all:
	$(CC) $(SOURCES) $(CFLAGS) -o tcp-tun
clean:
	rm -rf tcp-tun
