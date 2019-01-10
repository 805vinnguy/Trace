CC=gcc
CFLAGS=-Wall -g -pedantic

all: trace

trace: trace.c
	$(CC) $(CFLAGS) -o trace trace.c checksum.c

clean:
	rm -f trace
