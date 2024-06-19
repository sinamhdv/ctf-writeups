CC=gcc
CFLAGS=-Wall -s

all:
	$(CC) $(CFLAGS) -o chall game_of_luck.c
	patchelf --set-rpath . --set-interpreter ./ld-linux-x86-64.so.2 chall
