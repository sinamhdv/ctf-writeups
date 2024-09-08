CC=clang-17
WASI_SYSROOT=/wasi-sysroot
CFLAGS=--target=wasm32-unknown-wasi --sysroot $(WASI_SYSROOT) -O0 -g
OBJS=payload.o reader_patched.o writer_patched.o

all:
	docker run --rm -v `pwd`:/src -w /src ghcr.io/webassembly/wasi-sdk make payload

payload: payload.c
	$(CC) reader.c $(CFLAGS) -c -o reader.o
	$(CC) writer.c $(CFLAGS) -c -o writer.o
	$(CC) payload.c $(CFLAGS) -c -o payload.o
	$(CC) $(CFLAGS) $(OBJS) -o payload.wasm
	base64 payload.wasm -w 0 > payload.wasm.base64
	echo >> payload.wasm.base64
