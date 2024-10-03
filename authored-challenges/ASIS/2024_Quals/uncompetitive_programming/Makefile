CC=g++
# CFLAGS=-Wall -Wextra -g -DDEBUG
CFLAGS=-Wall -Wextra -s

SRCS = main.cpp

all:
	$(CC) $(CFLAGS) $(SRCS) -o chall
	patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . chall
