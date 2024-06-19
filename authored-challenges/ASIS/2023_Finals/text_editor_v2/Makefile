CC=gcc
CFLAGS=-Wall -no-pie -s

all:
	$(CC) $(CFLAGS) -o chall editor.c custom_string.h
	patchelf --set-rpath . --set-interpreter ./ld-linux-x86-64.so.2 chall
