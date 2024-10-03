CC=g++
# CFLAGS=-Wall -Wextra -g -fno-stack-protector
CFLAGS=-Wall -Wextra -s -fno-stack-protector

all:
	$(CC) $(CFLAGS) -o chall pizza.cpp
	patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . ./chall
