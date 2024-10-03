CC=gcc
# CFLAGS=-Wall -Wextra -g
CFLAGS=-Wall -Wextra -s

all:
	$(CC) $(CFLAGS) -o chall grades.c
	patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . chall
